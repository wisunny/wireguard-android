/*
 * Copyright © 2017-2025 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.activity

import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.util.Log
import android.view.LayoutInflater
import android.view.MenuItem
import android.view.View
import android.view.ViewGroup
import android.widget.EditText
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.fragment.app.commit
import androidx.lifecycle.lifecycleScope
import androidx.preference.EditTextPreference
import androidx.preference.EditTextPreferenceDialogFragmentCompat
import androidx.preference.Preference
import androidx.preference.PreferenceFragmentCompat
import com.wireguard.android.Application
import com.wireguard.android.QuickTileService
import com.wireguard.android.R
import com.wireguard.android.backend.WgQuickBackend
import com.wireguard.android.preference.PreferencesPreferenceDataStore
import com.wireguard.android.util.AdminKnobs
import com.wireguard.util.UdpDnsResolver
import java.net.InetAddress
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** Interface for changing application-global persistent settings. */
class SettingsActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (supportFragmentManager.findFragmentById(android.R.id.content) == null) {
            supportFragmentManager.commit { add(android.R.id.content, SettingsFragment()) }
        }
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        if (item.itemId == android.R.id.home) {
            finish()
            return true
        }
        return super.onOptionsItemSelected(item)
    }

    class SettingsFragment : PreferenceFragmentCompat() {

        // Since this is pretty much abandoned by androidx, it never got updated for proper
        // EdgeToEdge support,
        // which is enabled everywhere for API 35. So handle the insets manually here.
        override fun onCreateView(
                inflater: LayoutInflater,
                container: ViewGroup?,
                savedInstanceState: Bundle?
        ): View {
            val view = super.onCreateView(inflater, container, savedInstanceState)
            view.fitsSystemWindows = true
            return view
        }

        override fun onDisplayPreferenceDialog(preference: Preference) {
            if (preference.key == "custom_dns") {
                val f = CustomDnsPreferenceDialogFragment.newInstance(preference.key)
                f.setTargetFragment(this, 0)
                f.show(parentFragmentManager, "CustomDnsDialog")
            } else {
                super.onDisplayPreferenceDialog(preference)
            }
        }


        override fun onCreatePreferences(savedInstanceState: Bundle?, key: String?) {
            preferenceManager.preferenceDataStore =
                    PreferencesPreferenceDataStore(
                            lifecycleScope,
                            Application.getPreferencesDataStore()
                    )
            addPreferencesFromResource(R.xml.preferences)
            preferenceScreen.initialExpandedChildrenCount = 6

            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU || QuickTileService.isAdded) {
                val quickTile = preferenceManager.findPreference<Preference>("quick_tile")
                quickTile?.parent?.removePreference(quickTile)
                --preferenceScreen.initialExpandedChildrenCount
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                val darkTheme = preferenceManager.findPreference<Preference>("dark_theme")
                darkTheme?.parent?.removePreference(darkTheme)
                --preferenceScreen.initialExpandedChildrenCount
            }
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
                val remoteApps =
                        preferenceManager.findPreference<Preference>("allow_remote_control_intents")
                remoteApps?.parent?.removePreference(remoteApps)
            }
            if (AdminKnobs.disableConfigExport) {
                val zipExporter = preferenceManager.findPreference<Preference>("zip_exporter")
                zipExporter?.parent?.removePreference(zipExporter)
            }
            val wgQuickOnlyPrefs =
                    arrayOf(
                                    preferenceManager.findPreference("tools_installer"),
                                    preferenceManager.findPreference("restore_on_boot"),
                                    preferenceManager.findPreference<Preference>("multiple_tunnels")
                            )
                            .filterNotNull()
            wgQuickOnlyPrefs.forEach { it.isVisible = false }
            lifecycleScope.launch {
                if (Application.getBackend() is WgQuickBackend) {
                    ++preferenceScreen.initialExpandedChildrenCount
                    wgQuickOnlyPrefs.forEach { it.isVisible = true }
                } else {
                    wgQuickOnlyPrefs.forEach { it.parent?.removePreference(it) }
                }
            }
            preferenceManager.findPreference<Preference>("log_viewer")
                    ?.setOnPreferenceClickListener {
                        startActivity(Intent(requireContext(), LogViewerActivity::class.java))
                        true
                    }
            val kernelModuleEnabler =
                    preferenceManager.findPreference<Preference>("kernel_module_enabler")
            if (WgQuickBackend.hasKernelSupport()) {
                lifecycleScope.launch {
                    if (Application.getBackend() !is WgQuickBackend) {
                        try {
                            withContext(Dispatchers.IO) { Application.getRootShell().start() }
                        } catch (_: Throwable) {
                            kernelModuleEnabler?.parent?.removePreference(kernelModuleEnabler)
                        }
                    }
                }
            } else {
                kernelModuleEnabler?.parent?.removePreference(kernelModuleEnabler)
            }

            val customDnsPref = findPreference<EditTextPreference>("custom_dns")
            customDnsPref?.summaryProvider = EditTextPreference.SimpleSummaryProvider.getInstance()

        }
    }

    class CustomDnsPreferenceDialogFragment : EditTextPreferenceDialogFragmentCompat() {
        override fun onStart() {
            super.onStart()
            val dialog = dialog as? AlertDialog ?: return
            val positiveButton = dialog.getButton(AlertDialog.BUTTON_POSITIVE)
            positiveButton.setOnClickListener {
                val editText = dialog.findViewById<EditText>(android.R.id.edit)
                val text = editText?.text?.toString()?.trim() ?: ""
                val dns = validDns(text)
                if (dns == null) {
                    editText?.error = getString(R.string.custom_dns_invalid)
                } else {
                    UdpDnsResolver.setDnsServer(dns)
                    Log.i("WireGuardSettings", "用户设置的自定义 DNS: ${dns.hostAddress}")
                    (preference as EditTextPreference).text = text
                    dialog.dismiss()
                }
            }
        }

        private fun validDns(dns: String): InetAddress? {
            if (dns.isBlank()){
                return null
            }
            return try {
                InetAddress.getByName(dns)
            } catch (e: Exception) {
                null
            }
        }

        companion object {
            fun newInstance(key: String): CustomDnsPreferenceDialogFragment {
                val fragment = CustomDnsPreferenceDialogFragment()
                val bundle = Bundle(1)
                bundle.putString(ARG_KEY, key)
                fragment.arguments = bundle
                return fragment
            }
        }
    }

}
