from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from random import uniform
from datetime import datetime
from zoneinfo import ZoneInfo
import base64
import json
import hashlib

def SHA256(dados: str):
    return hashlib.sha256(dados.encode("utf-8")).digest()

class Base:

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

        self.chave_privada = pem_privado
        self.chave_publica = pem_publico
        self.copia_blockchain = copia_blockchain

    def carregar_chave_privada(self):
        """Carrega a chave privada do formato PEM para um objeto RSAPrivateKey."""
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


class Usuario(Base):

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
        """Cria uma transação"""
        transacao = {
            "id": "",
            "beneficiario": "",
            "chave_publica": base64.b64encode(self.chave_publica).decode('utf-8'),
            "quantidade": uniform(0.5, 10),
            "assinatura": "",
            "data_hora": datetime.now(ZoneInfo("America/Sao_Paulo")).isoformat(),
            "taxa": 0.0
        }

        transacao_copia = transacao.copy()
        transacao_copia = json.dumps(transacao_copia).encode("utf-8")
        transacao["id"] = SHA256(SHA256(transacao_copia))

        return transacao


class Minerador(Base):

    def criar_transacao_recompensa(self, soma_taxas: float, nonce=0):
        """Cria uma transação de recompensa para o minerador"""
        transacao = {
            "id": "",
            "beneficiario": self.chave_publica,
            "quantidade": 10.0 + soma_taxas, # Quantidade inicial que o minerador pode minerar
            "chave_publica": self.chave_publica,
            "assinatura": "",
            "data_hora": datetime.now(ZoneInfo("America/Sao_Paulo")).isoformat(),
            "nonce_extra": nonce
        }
    
        transacao_copia = transacao.copy()
        transacao_copia = json.dumps(transacao_copia).encode("utf-8")
        transacao["id"] = SHA256(SHA256(transacao_copia))
        
        return transacao
    
    def gerar_bloco(self, transacoes_do_bloco: list, hash_anterior: str, alvo_dificuldade):

        with open("blockchain.txt", "r") as arquivo:
            copia_blockchain = json.loads(arquivo)
            id = copia_blockchain[-1]["id"] + 1

        return {
            "id": id,
            "nonce": 0,
            "raiz_merkle": SHA256(SHA256(transacoes_do_bloco)),
            "hash_anterior": hash_anterior,
            "data_hora": datetime.now(ZoneInfo("America/Sao_Paulo")).isoformat(),
            "alvo_dificuldade": alvo_dificuldade,
            "transacoes": transacoes_do_bloco
        }