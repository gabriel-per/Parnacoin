import uuid
import base64
import json
import cryptography.exceptions
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import paho.mqtt.client as mqtt
from dateutil.parser import parse
from classes import Minerador, SHA256

# O padrão para armazenamento do blockchain Parnacoin é:
# [
#     {
#         "id": 0,
#         "nonce": número de 0 a 4,294,967,295 (32 bits),
#         "raiz_merkle": "Hash SHA256 das transações",
#         "hash_anterior": "Hash SHA256 do bloco anterior",
#         "data_hora": "objeto datetime",
#         "alvo_dificuldade": número da quantidade de 0s iniciais
#         "transacoes": [
#             {"id": , "beneficiario": , "chave_publica": , "quantidade": , "assinatura": , "data_hora": , "taxa": }
#         ]
#     },
#     {
#         "id": 1,
#         (...)
#         "transacoes": [
#             "transacoes aqui..."
#         ]
#     },
# ]
# Onde o blockchain é uma lista de objetos JSON, "id" é o id do bloco (sequencial, igual ao seu índice na lista), "transacoes" é uma lista de objetos JSON, e o nonce é o "número dourado" em SHA256.


transacoes_recebidas = []
alvo_dificuldade = 10


def checar_saldo(chave_publica: str, quantidade: float, taxa: float):
    """
    Checa se o pagador tem saldo suficiente para fazer uma transferência observando todo o seu histórico na blockchain.

    :param UUID pagadorUUID: UUID do pagador
    """
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
    

def checar_bloco(bloco: str):
    """
    Verifica a validade do bloco.

    :param str bloco: Bloco a ser validado
    """
    # A implementar:
    # - Validar se o SHA256 do bloco realmente atende à dificuldade
    # - Checar a validade do hash anterior (hash do header)
    # - Checar a validade da raiz Merkle (hash das transações)
    # - Checar a validade do ID
    # - Checar se data_hora existe e é maior do que o bloco anterior
    # - Checar se alvo_dificuldade é consistente com as regras da rede
    # - Checar se transacoes contém transações corretamente formatadas
    # - 

    bloco = json.loads(bloco)

    try:
        if (not (isinstance(bloco["id"], int) or isinstance())):
            pass
    except:
        pass


def checar_transacao(transacao: dict):
    """
    Verifica a validade da transação.

    :param dict transacao: Transação a ser validada
    """
    try:
        # Checa a validade dos UUIDs
        for i in ["id", "beneficiario"]:
            teste_uuid = uuid.UUID(transacao[i])
            if (teste_uuid.version != 4):
                return ValueError
            
        # Checa a validade do objeto datetime
        parse(transacao["data_hora"], fuzzy=False)

        # Checa se a quantidade e a taxa a ser transferida é válida
        if (transacao["quantidade"] <= 0 or not isinstance(transacao["taxa"], float) or not checar_saldo(transacao["pagador"], transacao["quantidade"], transacao["taxa"])):
            return ValueError
        
        # Carrega a chave pública
        public_key = serialization.load_pem_public_key(base64.b64decode(transacao["chave_publica"]))
        
        # Prepara a transação para verificação
        # (ela precisa ser verificada do jeito que foi assinada)
        transacao_sem_assinatura = transacao.copy()
        transacao_sem_assinatura["assinatura"] = ""
        mensagem = json.dumps(transacao_sem_assinatura, sort_keys=True).encode("utf-8")
        
        # Verifica a validade da assinatura
        try:
            public_key.verify(
                base64.b64decode(transacao["assinatura"]),
                mensagem,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )

            # Verifica se o pagador tem saldo suficiente para a transação
            if (not checar_saldo(transacao["chave_publica"], transacao["quantidade"], transacao["taxa"])):
                return ValueError
            
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
            
            if (checar_bloco(bloco)):
                pass


mqttc = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
mqttc.on_connect = ao_conectar
mqttc.on_message = mensagem_recebida

# Se inscreve na rede Parnacoin e na rede de blocos com Qualidade de Serviço 1 (1 confirmação de recebimento)
mqttc.connect("127.0.0.1", 1883, 60)
mqttc.subscribe("rede-parnacoin", 1)
mqttc.subscribe("rede-blocos", 1)
mqttc.loop_forever()