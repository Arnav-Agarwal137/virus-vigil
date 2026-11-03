rule SCRIPT_Dropper_Unknown_ForgeAuto_92950c6a
{
    meta:
        author = "Marjoriefort"
        description = "Detects Unknown (script_sh, etat binaire)"
        date = "2026-10-02"
        reference_sha256 = "92950c6a981e7e1b467ab773f6ae6613b24f298f0e9c9264b6c96e533f0b8e7c"
        yarahub_uuid = "d122a536-3f39-443a-ba05-44e87ff1dce3"
        famille = "unknown"
        famille_source = "inconnue"
        classe = "script_sh"
        etat = "binaire"
        confidence_suggeree = "medium"
        source = "forge_miss M3 v1.9.48"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "f0d11a3c262311fe2887383843578ec1"
        yarahub_reference_link = "https://github.com/Marjoriefort/yara-rules"
    strings:
        $s0 = "pip install onnxruntime opencv-python==4.5.4.60 pillow numpy==1.23.0 pyinstaller" ascii
        $s1 = "/bin/bash" ascii
        $s2 = "Creating venv" ascii
        $s3 = "PYTHON_BINARY=$(which python3)" ascii
        $s4 = "if [[ -z \"$PYTHON_BINARY\" ]]; then" ascii
        $s5 = "PYTHON_BINARY=$(which python)" ascii
        $s6 = "PYTHON_BINARY\" -m venv venv" ascii
        $s7 = "source venv/bin/activate" ascii
        $s8 = "pyinstaller --onedir --clean facetracker.py \\" ascii
        $s9 = "--add-binary venv/lib/python3.*/site-packages/onnxruntime/capi/*.so:onnxruntime/capi" ascii
        $s10 = "python3 not found. Searching for python instead." ascii
        $s11 = "Python 3 must be available on your path. Exiting." ascii
        $s12 = "Files should be available in the dist/ folder" ascii
        $s13 = "pip install wheel # Make sure this is installed beforehand" ascii
        $s14 = "Installing packages" ascii
        $s15 = "Creating binary" ascii
        $s16 = "set -e" ascii
    condition:
        true and filesize < 50MB and 2 of ($s1, $s2, $s3, $s4, $s5, $s6, $s7, $s8, $s9, $s10, $s11, $s12, $s13, $s14, $s15, $s16) and 1 of ($s0)
}
