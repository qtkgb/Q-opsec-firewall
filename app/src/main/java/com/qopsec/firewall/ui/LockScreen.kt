package com.qopsec.firewall.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.systemBarsPadding
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp

/**
 * Full-screen lock gate. [onUnlock] returns true if the passcode was correct. When [onBiometric] is
 * non-null, a "Use biometrics" button offers fingerprint/face unlock (the activity also auto-prompts
 * on each foreground); the passcode is always available as the fallback.
 */
@Composable
fun LockScreen(onUnlock: (String) -> Boolean, onBiometric: (() -> Unit)? = null) {
    var passcode by remember { mutableStateOf("") }
    var error by remember { mutableStateOf(false) }

    Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
        Column(
            modifier = Modifier.fillMaxSize().systemBarsPadding().padding(28.dp),
            verticalArrangement = Arrangement.Center,
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Text(
                text = "Q opsec firewall",
                style = MaterialTheme.typography.headlineSmall,
                fontWeight = FontWeight.Bold,
            )
            Spacer(Modifier.height(6.dp))
            Text(
                text = "Locked — enter your passcode",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(20.dp))
            OutlinedTextField(
                value = passcode,
                onValueChange = { passcode = it; error = false },
                label = { Text("Passcode") },
                singleLine = true,
                isError = error,
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                modifier = Modifier.fillMaxWidth(),
            )
            if (error) {
                Text(
                    text = "Incorrect passcode",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.error,
                    modifier = Modifier.padding(top = 6.dp),
                )
            }
            Spacer(Modifier.height(16.dp))
            Button(
                onClick = {
                    if (onUnlock(passcode)) { /* unlocked by caller */ } else {
                        error = true
                        passcode = ""
                    }
                },
                enabled = passcode.isNotEmpty(),
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Unlock") }
            if (onBiometric != null) {
                Spacer(Modifier.height(10.dp))
                TextButton(onClick = onBiometric, modifier = Modifier.fillMaxWidth()) {
                    Text("Use biometrics")
                }
            }
        }
    }
}
