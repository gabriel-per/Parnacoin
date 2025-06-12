import json
import paho.mqtt.client as mqtt
from classes import Usuario, SHA256

def ao_conectar(client, userdata, flags, reason_code, properties):
    print("Conectado à rede Parnacoin!")

mqttc = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
mqttc.on_connect = ao_conectar

# Se inscreve na rede Parnacoin com Qualidade de Serviço 1 (1 confirmação de recebimento)
mqttc.connect("127.0.0.1", 1883, 60)
mqttc.subscribe("rede-parnacoin", 1)

beneficiario = SHA256(SHA256())

a = Usuario()
transacao = a.criar_transacao("")
print(transacao)
mqttc.publish("rede-parnacoin", json.dumps(transacao))
print(json.dumps(transacao, indent=2))

mqttc.loop_forever()