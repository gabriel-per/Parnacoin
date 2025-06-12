import base64
import json
import cryptography.exceptions
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import paho.mqtt.client as mqtt
from dateutil.parser import parse
from classes import Minerador, SHA256

# O padrão para armazenamento do blockchain Parnacoin é:
# {
#     "0": [
#         {
#             "id": 0,
#             "nonce": número de 0 a 4,294,967,295 (32 bits),
#             "raiz_merkle": "Hash SHA256 das transações",
#             "hash_anterior": "Hash SHA256 do bloco anterior",
#             "data_hora": "objeto datetime",
#             "alvo_dificuldade": número da quantidade de 0s iniciais
#             "transacoes": [
#                 {"id": , "beneficiario": , "chave_publica": , "quantidade": , "assinatura": ,  "data_hora": , "taxa": }
#             ]
#         },
#         {
#             "id": 1,
#             (...)
#             "transacoes": [
#                 "transacoes aqui..."
#             ]
#         },
#     ]
# }
# Onde há uma dicionário da árvore de blockchains (onde o blockchain mais confiado é o "0"), o blockchain é uma lista de objetos JSON, "id" é o id do bloco (sequencial, igual ao seu índice na lista), "transacoes" é uma lista de objetos JSON, e o nonce é o "número dourado" em SHA256.


transacoes_recebidas = []
alvo_dificuldade = 10


def checar_saldo(chave_publica: str, quantidade: float, taxa: float):
    """Checa se o pagador tem saldo suficiente para fazer uma transferência observando todo o seu histórico na blockchain."""
    with open("blockchain.txt", "r") as arquivo:
        copia_blockchain = arquivo.read()
        # Procura todos os índices das ocorrências do ID do pagador (chave pública) na blockchain
        copia_blockchain = json.loads(copia_blockchain)

        # Soma todas as transações
        soma = 0
        if (taxa > 0):
            soma += taxa
        for bloco in copia_blockchain:
            for transacao in bloco["transacoes"]:
                if transacao["chave_publica"] == chave_publica:
                    soma += transacao["quantidade"]

        if (soma - quantidade < 0):
            return False
        return True
    

def checar_bloco(bloco):
    global alvo_dificuldade
    """Verifica a validade do bloco."""
    # A implementar:
    # - Validar se o SHA256 do bloco realmente atende à dificuldade
    # - Checar a validade do hash anterior (hash do header)
    # - Checar a validade da raiz Merkle (hash das transações)
    # - Checar a validade do ID
    # - Checar se data_hora existe e é maior do que o bloco anterior
    # - Checar se alvo_dificuldade é consistente com as regras da rede
    # - Checar se transacoes contém transações corretamente formatadas
    # - Checar se a transação de recompensa está presente e é válida

    with open("blockchain.txt", "rw") as arquivo:
        copia_blockchain = arquivo.read()
        copia_blockchain = json.loads(copia_blockchain)

    try:
        # Mesmo se o bloco for válido e encaixar na blockchain existente, ainda pode ser uma fraude de double spending (gasto duplo), onde um indivíduo transmite um bloco a apenas uma pessoa, dando a entender que ela a pagou, sendo que ele não transmitiu o bloco para o restante da rede, e portanto é uma transação inválida. A fim de garantir a validade da transação, é importante escutar por novos blocos, e não confiar em blocos novos imediatamente.
        # Portanto, devemos admitir que a blockchain desenvolva bifurcações em até 4 blocos atrás do mais recente.
        if (not (isinstance(bloco["id"], int) and isinstance(bloco["nonce"], int) and isinstance(bloco["hash_anterior"], str) and len(bloco["hash_anterior"] == 64) and len(bloco["raiz_merkle"] == 64) and (bloco["alvo_dificuldade"] == alvo_dificuldade))):
            raise ValueError("ID, nonce, hash anterior, raiz merkle ou alvo_dificuldade incorretamente formatados")
        
        if (bloco["transacoes"] == []):
            raise ValueError("O bloco deve conter pelo menos uma transação!")
        
        c = 0
        for transacao in bloco["transacoes"]:
            int(transacao["id"], 16)

            if (c == 0):
                if (not (isinstance(transacao["nonce_extra"], int) and 
                (bloco["chave_publica"] == bloco["beneficiario"]))):
                    raise ValueError("Transação de recompensa inexistente ou inválida!")

            serialization.load_pem_public_key(base64.b64decode(transacao["beneficiario"]))
            serialization.load_pem_public_key(base64.b64decode(transacao["chave_publica"]))
            if (len(transacao["id"]) != 64 or bloco["quantidade"] <= 0 or bloco["beneficiario"] or transacao["data_hora"] <= bloco["data_hora"] or not Minerador.validar_assinatura(transacao)):
                raise ValueError
        
        if (bloco["transacoes"][0]):
            pass
        
        # Verifica se o hash anterior, id e raiz merkle estão em hexadecimal
        int(bloco["hash_anterior"], 16)
        int(bloco["raiz_merkle"], 16)

        hash = int(SHA256(SHA256(bloco)), 16)
        hash_binario = bin(hash)[2:].zfill(256)
        if (len(hash_binario) - len(hash_binario.lstrip("0")) < alvo_dificuldade):
            raise ValueError("Dificuldade de mineração incorreta!")

        # Verifica se o bloco se encaixa na blockchain
        chave_blockchain = -1
        for chave in copia_blockchain:
            for c in [-1, -2, -3, -4]:
                if (SHA256(SHA256(copia_blockchain[chave][c]["hash_anterior"])) == bloco["hash_anterior"]):
                    if (copia_blockchain[chave][c]["data_hora"] > bloco["data_hora"]):
                        raise ValueError("Bloco não pode ser minerado antes do seu antecessor")
                    chave_blockchain = chave
                    break
            
        if (chave_blockchain == -1):
            raise ValueError

    except Exception as e:
        print(e)
        return False
    
    return True


def checar_transacao(transacao: dict):
    """Verifica a validade da transação."""
    try:
        # Verifica se a chave pública do beneficiário é válida
        chave_publica = serialization.load_pem_public_key(base64.b64decode(transacao["beneficiario"]))
            
        # Checa a validade do objeto datetime
        parse(transacao["data_hora"], fuzzy=False)

        # Checa se a quantidade e a taxa a ser transferida é válida
        if (transacao["quantidade"] <= 0 or not isinstance(transacao["taxa"], float) or not checar_saldo(transacao["pagador"], transacao["quantidade"], transacao["taxa"])):
            raise ValueError
        
        # Carrega a chave pública do pagador (e verifica sua validade)
        chave_publica = serialization.load_pem_public_key(base64.b64decode(transacao["chave_publica"]))
        
        try:
            # Verifica se o pagador tem saldo suficiente para a transação e se a assinatura é válida
            if (not (checar_saldo(transacao["chave_publica"], transacao["quantidade"], transacao["taxa"]) and Minerador.validar_assinatura(transacao))):
                raise ValueError
            
            print("Transação válida recebida!")
            return True
        
        except cryptography.exceptions.InvalidSignature as e:
            print("ERRO: Transação inválida!")
            return False
        
    except ValueError as e:
        print(f"Transação inválida: {e}")
        return False
    
    except Exception as e:
        print(f"Erro inesperado: {e}")
        return False
    

def minerar_bloco(hash_anterior, mempool):
    """Minera um novo bloco"""

    # Ordena transações da mempool por taxa (o minerador prioriza as transações mais lucrativas)
    transacoes_ordenadas = sorted(mempool, key=lambda transacao: transacao.get('taxa', 0),reverse=True)
    # Limita em 100 transações por bloco
    transacoes_selecionadas = transacoes_ordenadas[:100]
        
    soma_taxas = 0
    for transacao in mempool:
        soma_taxas += transacao["taxa"]

    # Transação que premia o minerador
    transacao_recompensa = Minerador.criar_transacao_recompensa(soma_taxas)

    # Bloco conterá a recompensa mais as transações selecionadas
    transacoes_do_bloco = [transacao_recompensa]+transacoes_selecionadas

    global alvo_dificuldade
    novo_bloco = Minerador.gerar_bloco(transacoes_do_bloco, hash_anterior, alvo_dificuldade)

    # Processo de Proof of Work
    while True:
        # Todo bloco precisa ser "hashado" duas vezes. Não é estritamente necessário,
        # mas protege a criptomoeda de ataques de extensão de hash. "Hashar" duas vezes
        # impossibilita esse tipo de ataque.
        tentativa_hash = SHA256(SHA256(novo_bloco))
        if (tentativa_hash.startswith(alvo_dificuldade)):
            return novo_bloco
        novo_bloco["nonce"] += 1


######## v Implementação do MQTT v ########

def ao_conectar(client, userdata, flags, reason_code, properties):
    print("Conectado!")


def mensagem_recebida(client, userdata, msg):
    print(msg.payload.decode("utf-8"))

    match (msg.topic):

        case "rede-parnacoin":
            global transacoes_recebidas
            transacao = json.loads(msg.payload.decode("utf-8"))

            if (checar_transacao(transacao)):
                transacoes_recebidas.append(transacao)
                print("Transação recebida")
                print(msg.topic+" "+str(msg.payload))
                
        case "rede-blocos":
            if (checar_bloco(json.loads(msg.payload.decode("utf-8")))):
                pass


mqttc = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
mqttc.on_connect = ao_conectar
mqttc.on_message = mensagem_recebida

# Se inscreve na rede Parnacoin e na rede de blocos com Qualidade de Serviço 1 (1 confirmação de recebimento)
mqttc.connect("127.0.0.1", 1883, 60)
mqttc.subscribe("rede-parnacoin", 1)
mqttc.subscribe("rede-blocos", 1)
mqttc.loop_forever()