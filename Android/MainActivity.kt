package com.example.encryptedchat

import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.viewModels
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView

class MainActivity : ComponentActivity() {

    private val viewModel: ChatViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val recycler = findViewById<RecyclerView>(R.id.recyclerMessages)
        val editMessage = findViewById<EditText>(R.id.editMessage)
        val buttonSend = findViewById<Button>(R.id.buttonSend)

        val adapter = ChatAdapter(emptyList())
        recycler.adapter = adapter
        recycler.layoutManager = LinearLayoutManager(this)

        viewModel.messages.observe(this) { list ->
            adapter.submitList(list)
            recycler.scrollToPosition(list.size - 1)
        }

        buttonSend.setOnClickListener {
            val text = editMessage.text.toString()
            if (text.isBlank()) {
                Toast.makeText(this, "Message cannot be empty", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            try {
                viewModel.sendMessage(text)
                editMessage.text.clear()
            } catch (e: Exception) {
                Toast.makeText(this, "Encryption error", Toast.LENGTH_SHORT).show()
            }
        }
    }
}