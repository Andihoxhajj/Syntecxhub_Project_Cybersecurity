package com.example.encryptedchat

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView

class ChatAdapter(
    private var items: List<ChatMessage>
) : RecyclerView.Adapter<ChatAdapter.VH>() {

    class VH(view: View) : RecyclerView.ViewHolder(view) {
        val textPlain: TextView = view.findViewById(R.id.textPlain)
        val textCipher: TextView = view.findViewById(R.id.textCipher)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): VH {
        val v = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_message, parent, false)
        return VH(v)
    }

    override fun onBindViewHolder(holder: VH, position: Int) {
        val msg = items[position]
        val direction = if (msg.isOutgoing) "You" else "Them"
        holder.textPlain.text = "$direction: ${msg.plaintext}"
        holder.textCipher.text = "AES (Base64): ${msg.ciphertextBase64}"
    }

    override fun getItemCount(): Int = items.size

    fun submitList(newItems: List<ChatMessage>) {
        items = newItems
        notifyDataSetChanged()
    }
}