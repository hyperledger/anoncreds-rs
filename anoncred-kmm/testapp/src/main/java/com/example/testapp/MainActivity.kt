package com.example.testapp

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import anoncreds_wrapper.Prover

class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        try {
            val prover = Prover()
            val linkSecret = prover.createLinkSecret()
            println(linkSecret.getValue())
        } catch (ex: Throwable) {
            throw ex
        }
    }
}
