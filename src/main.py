import paho.mqtt.client as mqtt

def on_connect(client, userdata, flags, rc):
    print(f"Connecté au broker MQTT avec le code de retour {rc}")
    client.subscribe("iot/security") # On s'abonne au topic MQTT

def on_message(client,userdata,msg):
    print(f"Message reç sur {msg.topic}: {msg.payload.decode()}")

client = mqtt.Client()
client.on_connect = on_connect
client.on_message = on_message

client.connect("test.mosquitto.org", 1883, 60)
client.loop_forever() # Boucle infinie pour écouter les messages 