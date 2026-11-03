rule MULTI_Sample_Unique_3ae99d74
{
    meta:
        author = "Marjoriefort"
        description = "Detects Unknown (inconnu, etat binaire)"
        date = "2026-10-02"
        reference_sha256 = "3ae99d74020b7c6e5cd19b9d1431f07cffdf4b2d320b59e239e92ff48584cd97"
        yarahub_uuid = "67e30d3b-9263-4700-9889-a5e206b401c5"
        famille = "unknown"
        famille_source = "inconnue"
        classe = "inconnu"
        etat = "binaire"
        confidence_suggeree = "low"
        source = "forge_miss M3 v1.9.48"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "6b28547058651df79659d757f5a05818"
        yarahub_reference_link = "https://github.com/Marjoriefort/yara-rules"
    strings:
        $s0 = "import react from '@vitejs/plugin-react'" ascii
        $s1 = "host: '127.0.0.1'," ascii
        $s2 = "target: 'http://127.0.0.1:8765'," ascii
        $s3 = "import { defineConfig } from 'vite'" ascii
        $s4 = "export default defineConfig({" ascii
        $s5 = "plugins: [react()]," ascii
        $s6 = "changeOrigin: true," ascii
        $s7 = "outDir: 'dist'," ascii
        $s8 = "emptyOutDir: true," ascii
        $s9 = "server: {" ascii
        $s10 = "port: 5173," ascii
        $s11 = "proxy: {" ascii
        $s12 = "ws: true," ascii
        $s13 = "build: {" ascii
    condition:
        true and filesize < 50MB and 3 of ($s0, $s3, $s4, $s5, $s6, $s7, $s8, $s9, $s10, $s11, $s12, $s13) and 1 of ($s1, $s2)
}
