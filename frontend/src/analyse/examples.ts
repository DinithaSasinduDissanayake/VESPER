// Three example texts for the Analyse page buttons.
export type Example = { label: string; text: string }

export const examples: Example[] = [
  {
    // NVD description of CVE-2024-3400 (PAN-OS GlobalProtect).
    label: 'Real CVE (CVE-2024-3400)',
    text: 'A command injection as a result of arbitrary file creation vulnerability in the GlobalProtect feature of Palo Alto Networks PAN-OS software for specific PAN-OS versions and distinct feature configurations may enable an unauthenticated attacker to execute arbitrary code with root privileges on the firewall. Cloud NGFW, Panorama appliances, and Prisma Access are not impacted by this vulnerability.',
  },
  {
    // Off-topic text: the model refuses to score it.
    label: 'Off-topic (pancake recipe)',
    text: 'Whisk the flour, sugar and a pinch of salt in a bowl. Add the eggs and milk and stir until the batter is smooth. Fry spoonfuls in a hot buttered pan until golden on both sides.',
  },
  {
    // Based on CVE-2023-27997, with leak wording added to show the masking.
    label: 'With leak wording',
    text: 'A heap-based buffer overflow vulnerability in FortiOS SSL-VPN may allow a remote attacker to execute arbitrary code or commands via specifically crafted requests. This issue has been exploited in the wild and was added to the CISA KEV catalog. A public exploit is listed at https://www.fortiguard.com/psirt/FG-IR-23-097.',
  },
]
