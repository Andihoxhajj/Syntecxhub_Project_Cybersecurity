package com.example.encryptedchat

import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel

class ChatViewModel : ViewModel() {

    private val cryptoManager = CryptoManager()

    private val _messages = MutableLiveData<List<ChatMessage>>(emptyList())
    val messages: LiveData<List<ChatMessage>> = _messages

    private var nextId = 1L

    fun sendMessage(text: String) {
        if (text.isBlank()) return

        try {
            val cipherB64 = cryptoManager.encryptToBase64(text)
            val msg = ChatMessage(
                id = nextId++,
                plaintext = text,
                ciphertextBase64 = cipherB64,
                isOutgoing = true
            )
            _messages.value = _messages.value.orEmpty() + msg

            // Optional: simulate a reply for demo/screenshots
            simulateReply(text)

        } catch (e: Exception) {
            // For error handling, you can expose an error LiveData to the Activity
            e.printStackTrace()
        }
    }

    private fun simulateReply(originalText: String) {
        val replyText = "Echo: $originalText"
        try {
            val cipherB64 = cryptoManager.encryptToBase64(replyText)
            val msg = ChatMessage(
                id = nextId++,
                plaintext = replyText,
                ciphertextBase64 = cipherB64,
                isOutgoing = false
            )
            _messages.value = _messages.value.orEmpty() + msg
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }
}