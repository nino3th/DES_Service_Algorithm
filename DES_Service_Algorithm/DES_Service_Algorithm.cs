/*
 *  LiteON-ModuleTeam RF-Chamber DES_Service_Algorithm DLL.
 *  
 *  Copyright (c)  NinoLiu\LiteON , Inc 2012
 * 
 *  Description:
 *      In order to encrypt for TIS/TRP data, to adopt DES(Data Encrypt Standard) algorithm to deal with 
 *    the behavior of the encryption and decryption.
 *    
 * ======================================================================================================
 * History
 * ----------------------------------------------------------------------------------------------------
 * 20120731  | NinoLiu  | 1.0.0  | Release first version for user terminal integration.
 * ----------------------------------------------------------------------------------------------------
 * ======================================================================================================
 */

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Security;
using System.IO;

namespace DES_SA
{
    public class DES_Service_Algorithm
    {
        public DES_Service_Algorithm()
        {
        }
        public string Encoding_Service(string enter_string)
        {
            // Create a new DES key
            DESCryptoServiceProvider des = new DESCryptoServiceProvider();
            string key = "abcdefgh";
            string iv = "12345678";
            //transform key to bytes
            des.Key = Encoding.ASCII.GetBytes(key);
            //transform vector to bytes
            des.IV = Encoding.ASCII.GetBytes(iv);
            //transform input string to bytes
            byte[] s = Encoding.Default.GetBytes(enter_string);
            //create a memory stream
            MemoryStream ms = new MemoryStream();

            //Encrypt//
            //package 'input string' into encrypt stream object. create a CryptoStream using the memory stream and the CSP DES Key.
            CryptoStream csEncrypt = new CryptoStream(ms, des.CreateEncryptor(des.Key, des.IV), CryptoStreamMode.Write);
            //CryptoStream csEncrypt = new CryptoStream(ms, des.CreateEncryptor(des.Key, des.IV), CryptoStreamMode.Write);

            //creates a symmetric data encryption statndard. 
            ICryptoTransform desencrypt = des.CreateEncryptor();

            ms.Close();
            // Transforms the specified region of the specified byte array, in order to separate by using "_" symbol.
            return BitConverter.ToString(desencrypt.TransformFinalBlock(s, 0, s.Length)).Replace("_", string.Empty);
        }
        public string Decoding_Service(string encrypt_code)
        {
            int j = 0;
            string temp_string = "_";
            string hexstring = encrypt_code;
            string key = "abcdefgh";
            string iv = "12345678";

            DESCryptoServiceProvider des = new DESCryptoServiceProvider();
            MemoryStream ms = new MemoryStream();

            des.Key = Encoding.ASCII.GetBytes(key);
            des.IV = Encoding.ASCII.GetBytes(iv);

            byte[] dd = new byte[(hexstring.Length / 3) + 1];

            for (int i = 0; i < (hexstring.Length / 3 + 1); i++)
            {
                temp_string = hexstring[j].ToString() + hexstring[j + 1].ToString();
                dd[i] = Byte.Parse(temp_string, System.Globalization.NumberStyles.HexNumber);
                j += 3;
            }

            CryptoStream cs = new CryptoStream(ms, des.CreateDecryptor(des.Key, des.IV), CryptoStreamMode.Write);

            cs.Write(dd, 0, dd.Length);
            cs.FlushFinalBlock();

            cs.Close();

            return System.Text.Encoding.Default.GetString(ms.ToArray());
        }                
    }
}
