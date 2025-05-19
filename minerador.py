import base64
import uuid
import base64
import json
import hashlib
import cryptography.exceptions
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from datetime import datetime
import paho.mqtt.client as mqtt
from dateutil.parser import parse
from re import finditer
from zoneinfo import ZoneInfo

# O padrão para armazenamento do blockchain Parnacoin é:
# {
#     "0": {
#         "transacoes": {
#             {"id": , "beneficiario": , "chave_publica": , "quantidade": , "assinatura": , "data_hora": }
#         },
#         "hash": "SHA256"
#     },
#     "1": {
#         "transacoes": {
#             "transacoes aqui..."
#         },
#         "hash": "SHA256"
#     },
# }
# Onde o número do bloco é o seu ID, "transacoes" é um array de objetos JSON, e o hash é o "número dourado" em SHA256.


transacoes_recebidas = []


class Bloco:

    def __init__(self,indice,hash_anterior,transacoes,data_hora=None,nonce=0):
        self.indice = indice
        self.data_hora = data_hora or datetime.utcnow().isoformat()
        self.hash_anterior = hash_anterior
        self.transacoes = transacoes
        self.nonce = nonce
        self.hash = None

    def calcular_hash(self):
        # Gera uma string JSON com os dados do bloco ordenados, codifica e calcula o hash SHA-256
        bloco_str = json.dumps({
            "indice": self.indice,
            "data_hora": self.data_hora,
            "hash_anterior": self.hash_anterior,
            "transacoes": self.transacoes,
            "nonce": self.nonce
        }, sort_keys=True).encode()
        return hashlib.sha256(bloco_str).hexdigest()


def checar_saldo(chave_publica: str, quantidade: float):
    """
    Checa se o pagador tem saldo suficiente para fazer uma transferência observando todo o seu histórico na blockchain.

    :param UUID pagadorUUID: UUID do pagador
    """
    with open("blockchain.txt", "r") as arquivo:
        copia_blockchain = arquivo.read()
        # Procura todos os índices das ocorrências do ID do pagador no blockchain
        copia_blockchain = json.loads(copia_blockchain)

        # Soma todas as transações
        soma = 0
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

        # Checa se a quantidade a ser transferida é válida
        if (transacao["quantidade"] <= 0 or not checar_saldo(transacao["pagador"])):
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
            if (not checar_saldo(transacao["chave_publica"], transacao["quantidade"])):
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
    

def minerar_bloco(cadeia_blocos, mempool, usuario_minerador):
    # Ordena transações da mempool por taxa
    transacoes_ordenadas = sorted(mempool,key=lambda tx: tx.get('taxa',0),reverse=True)
    # Limita em 100 transações por bloco
    transacoes_selecionadas = transacoes_ordenadas[:100]

    id_minerador = str(usuario_minerador.id_carteira)
    chave_publica_minerador = base64.b64encode(usuario_minerador.chave_publica).decode('utf-8')

    # Transação que premia o minerador
    transacao_recompensa = {
        "id": str(uuid.uuid4()),
        "pagador": None,
        "beneficiario": id_minerador,
        "quantidade": 10.0, # Quantidade inicial que o minerador pode minerar
        "taxa": 0.0,
        "chave_publica": chave_publica_minerador,
        "assinatura": "",
        "data_hora": datetime.now(ZoneInfo("America/Sao_Paulo")).isoformat()
    }

    # Bloco conterá a recompensa mais as transações selecionadas
    transacoes_do_bloco = [transacao_recompensa]+transacoes_selecionadas
    bloco_anterior = cadeia_blocos[-1]

    novo_bloco = Bloco(
        indice=bloco_anterior.indice + 1,
        hash_anterior=bloco_anterior.hash,
        transacoes=transacoes_do_bloco
    )

    # Quantidade de zeros iniciais no hash
    dificuldade = "0"*10

    # Processo de prova de trabalho
    while True:
        tentativa_hash = novo_bloco.calcular_hash()
        if(tentativa_hash.startswith(dificuldade)):
            novo_bloco.hash = tentativa_hash
            return novo_bloco
        novo_bloco.nonce+=1


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