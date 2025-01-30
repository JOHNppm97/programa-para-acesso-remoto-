import os
import socket
import ssl
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import cv2
import time
from datetime import datetime
import random
import string
import sqlite3
import pyautogui
from cryptography.fernet import Fernet
import bcrypt
import ttkbootstrap as tb

# Verificação e geração de chave de criptografia AES
KEY_FILE = "chave.key"


def carregar_ou_gerar_chave():
    if not os.path.exists(KEY_FILE):
        chave = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(chave)
    else:
        with open(KEY_FILE, "rb") as f:
            chave = f.read()
    return Fernet(chave)


fernet = carregar_ou_gerar_chave()


# Conexão segura com o banco de dados
def conectar_bd():
    conn = sqlite3.connect("acesso_remoto.db", check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario TEXT UNIQUE,
            senha TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS historico_acessos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario TEXT,
            data_hora TEXT,
            sucesso INTEGER
        )
    """)
    conn.commit()
    return conn


def registrar_historico(usuario, sucesso):
    conn = conectar_bd()
    cursor = conn.cursor()
    data_hora = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("INSERT INTO historico_acessos (usuario, data_hora, sucesso) VALUES (?, ?, ?)",
                   (usuario, data_hora, sucesso))
    conn.commit()
    conn.close()


# Senha segura
def hash_senha(senha):
    return bcrypt.hashpw(senha.encode(), bcrypt.gensalt()).decode()


def verificar_senha(senha, hash_senha):
    return bcrypt.checkpw(senha.encode(), hash_senha.encode())


# Interface gráfica aprimorada
root = tb.Window(themename="darkly")
root.title("Acesso Remoto - Login")
root.geometry("350x250")
root.resizable(False, False)

frame = ttk.Frame(root, padding=20)
frame.pack()

label_usuario = ttk.Label(frame, text="Usuário:")
label_usuario.grid(row=0, column=0, sticky="w")
entry_usuario = ttk.Entry(frame)
entry_usuario.grid(row=0, column=1)

label_senha = ttk.Label(frame, text="Senha:")
label_senha.grid(row=1, column=0, sticky="w")
entry_senha = ttk.Entry(frame, show="*")
entry_senha.grid(row=1, column=1)

login_tentativas = 0


def login():
    global login_tentativas
    usuario = entry_usuario.get()
    senha = entry_senha.get()
    conn = conectar_bd()
    cursor = conn.cursor()
    cursor.execute("SELECT senha FROM usuarios WHERE usuario = ?", (usuario,))
    resultado = cursor.fetchone()
    conn.close()

    if resultado and verificar_senha(senha, resultado[0]):
        registrar_historico(usuario, 1)
        messagebox.showinfo("Login", "Login bem-sucedido!")
    else:
        login_tentativas += 1
        registrar_historico(usuario, 0)
        if login_tentativas >= 3:
            messagebox.showerror("Erro", "Muitas tentativas falhas. Tente mais tarde.")
            root.quit()
        else:
            messagebox.showwarning("Erro", "Usuário ou senha inválidos!")


btn_login = ttk.Button(frame, text="Login", command=login)
btn_login.grid(row=2, column=0, columnspan=2, pady=10)

root.mainloop()

