package com.arnav.virusvigil

import android.content.res.Configuration
import android.graphics.Color
import android.os.Bundle
import android.view.View
import androidx.activity.enableEdgeToEdge
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat

class MainActivity : TauriActivity() {
  override fun onCreate(savedInstanceState: Bundle?) {
    enableEdgeToEdge()
    super.onCreate(savedInstanceState)
    // Edge-to-edge drew the page under the status bar, so the top card sat exactly where a tap
    // opens the notification shade (his Vivo, 29 Sep). Keep the page clear of the phone's bars;
    // the strip behind them takes the page's own background (--bg) so nothing looks cut off.
    val root = findViewById<View>(android.R.id.content)
    val night = (resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK) == Configuration.UI_MODE_NIGHT_YES
    root.setBackgroundColor(Color.parseColor(if (night) "#05070f" else "#eef2fb"))
    ViewCompat.setOnApplyWindowInsetsListener(root) { v, insets ->
      val b = insets.getInsets(WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout())
      v.setPadding(b.left, b.top, b.right, b.bottom)
      WindowInsetsCompat.CONSUMED
    }
  }
}
