import paho.mqtt.client as mqtt
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP 
import time
import logging
import yaml

# Dictionnaiure pour suivre les adresses IP et les timestamps des paquets reçus
ip_count = defaultdict(list)

# Seuil de paquets par seconde pour identifier une attaque DDoS
DDOS_THRESHOLD = 100 # nombre de paquets

# Charger la config
with open("config/config.yaml", "r") as file:
    config = yaml.safe_load(file)

# Configurer les logs
logging.basicConfig(filename=config["logging"]['log_file'], level=logging.INFO, 
                    format="%(asctime)s - %(levelname)s - %(message)s")


def on_connect(client, userdata, flags, rc):
    print(f"Connecté au broker MQTT avec le code de retour {rc}")
    client.subscribe(config["mqtt"]["topic"]) # On s'abonne au topic MQTT

def on_message(client,userdata,msg):
    print(f"Message reç sur {msg.topic}: {msg.payload.decode()}")

# Détection d'intrusion
def packet_callback(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "OTHER" 

    # Détection de paquets surspects 
    if packet.haslayer(TCP) and packet[TCP].flags == 2 : # SYN scan possible
        alert = f"[ALERT] SYN scan détecté de {src_ip} vers {dst_ip}"
        print(alert)
        logging.warning(alert)

    logging.info(f"Paquet capturé: {src_ip} -> {dst_ip} ({proto})")


def detect_ddos(packet):
    src_ip = packet[IP].src
    ip_count[src_ip].append(time.time())

    valid_timestamps = []

    for timestamp in ip_count[src_ip]:
        if timestamp > time.time() - 1: # Si le timestamp 
            valid_timestamps.append(timestamp)

    ip_count[src_ip] = valid_timestamps

    if len(ip_count[src_ip]) > DDOS_THRESHOLD:
        return True
    return False

# Lancer la capture réseau
def start_sniffing():
    print("Démarrage de la surveillance réseau... ")
    sniff(prn=packet_callback, store=False)

client = mqtt.Client()
client.on_connect = on_connect
client.on_message = on_message

client.connect(config["mqtt"]["broker"], config["mqtt"]["port"], 60)
client.loop_start() # Executer MQTT en arrière plan

# Lancer la capture réseau
start_sniffing()