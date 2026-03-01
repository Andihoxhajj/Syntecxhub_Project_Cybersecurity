package com.example.encryptedchat

data class ChatMessage(
    val id: Long,
    val plaintext: String,
    val ciphertextBase64: String,
    val isOutgoing: Boolean
)