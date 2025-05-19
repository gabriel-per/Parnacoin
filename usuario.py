import base64
import uuid
import base64
import json
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from random import uniform
from datetime import datetime
from zoneinfo import ZoneInfo
import paho.mqtt.client as mqtt

def ao_conectar(client, userdata, flags, reason_code, properties):
    print("Conectado!")

mqttc = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
mqttc.on_connect = ao_conectar

# Se inscreve na rede Parnacoin com Qualidade de Serviço 1 (1 confirmação de recebimento)
mqttc.connect("127.0.0.1", 1883, 60)
mqttc.subscribe("rede-parnacoin", 1)


class Usuario:

    def __init__(self):
        chave_privada = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
        )
        chave_publica = chave_privada.public_key()

        pem_privado = chave_privada.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        pem_publico = chave_publica.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        with open('blockchain.txt', 'r') as arquivo:
            copia_blockchain = arquivo.read()

        self.id_carteira = uuid.uuid4()
        self.chave_privada = pem_privado
        self.chave_publica = pem_publico
        self.copia_blockchain = copia_blockchain

    def carregar_chave_privada(self):
        """Carrega a chave privada do formato PEM para um objeto RSAPrivateKey"""
        return serialization.load_pem_private_key(
            self.chave_privada,
            password=None,
            backend=default_backend()
        )

    def assinar(self):
        # Carrega a chave privada corretamente
        chave_privada_obj = self.carregar_chave_privada()

        # Criar a transação
        transacao = self.criar_transacao()
        
        # Serializa a mensagem para assinar
        mensagem = json.dumps(transacao, sort_keys=True).encode('utf-8')

        # Assina a mensagem
        assinatura = chave_privada_obj.sign(
            mensagem,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        transacao["assinatura"] = base64.b64encode(assinatura).decode('utf-8')

        return transacao

    def criar_transacao(self):
        return {
            "id": str(uuid.uuid4()),  # Converte UUID para string
            "beneficiario": str(uuid.uuid4()),
            "chave_publica": base64.b64encode(self.chave_publica).decode('utf-8'),
            "quantidade": uniform(0.5, 10),
            "assinatura": "",
            "data_hora": datetime.now(ZoneInfo("America/Sao_Paulo")).strftime('%Y-%m-%d %H:%M:%S')
        }


a = Usuario()
transacao = a.assinar()
print(transacao)
mqttc.publish("rede-parnacoin", json.dumps(transacao))
print(json.dumps(transacao, indent=2))

mqttc.loop_forever()