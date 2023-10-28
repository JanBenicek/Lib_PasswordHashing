using System.Security.Cryptography;
using System.Text;

namespace Lib_PasswordHashing
{
    public class PasswordHashing
    {
        private readonly char[] SaltChars;
        private readonly HashAlgorithm Algorithm;

        /// <summary>
        /// Initialize Password hashing function
        /// </summary>
        /// <param name="algorithm">Hashing algorithm</param>
        /// <param name="saltChars">Chars for generate salt in string form</param>
        public PasswordHashing(HashAlgorithm? algorithm = null, string saltChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
        {
            if (algorithm == null)
            {
                Algorithm = SHA512.Create();    //if not specified use default SHA512
            }
            else
            {
                Algorithm = algorithm;  //if algorithm specified use them
            }

            SaltChars = saltChars.ToCharArray();    //convert salt chars string to array for use him
        }

        /// <summary>
        /// Hash password with salt
        /// </summary>
        /// <param name="password">Password string</param>
        /// <returns>Password hash and salt</returns>
        public HashedPassword HashPass(string password)
        {
            HashedPassword hp = GenerateSaltedPassword(password);   //Generate Salted Password and salt
            byte[] sp = Encoding.UTF32.GetBytes(hp.Hash);   //Convert salted password to Byte array

            byte[] hash = Algorithm.ComputeHash(sp);    //Compute hash
            hp.Hash = Convert.ToBase64String(hash);     //Convert Byte array to hash

            return hp;  //return hash and salt
        }

        /// <summary>
        /// Compare password with hash and salt
        /// </summary>
        /// <param name="password">password</param>
        /// <param name="Hash">hash</param>
        /// <param name="Salt">salt</param>
        /// <returns>Hash and Pass with salt same?</returns>
        public bool VerifyPass(string password, string Hash, string Salt)
        {
            string hash = Convert.ToBase64String( Algorithm.ComputeHash( Encoding.UTF8.GetBytes( GenerateSaltedPassword(password, Salt.ToArray()) ) ) );    //generate hash from password and salt

            if (hash == Hash)   //is password correct?
            {
                return true;    //yes
            }
            else //or
            {
                return false;   //no
            }
        }




        /// <summary>
        /// Generate new salted Password
        /// </summary>
        /// <param name="password">Password</param>
        /// <returns>Salted password and salt</returns>
        private HashedPassword GenerateSaltedPassword(string password)
        {
            char[] passwordSalt = GenerateSalt(password.Length);    //Generate password salt

            return new HashedPassword() { Hash = GenerateSaltedPassword(password, passwordSalt), Salt = new string(passwordSalt) };   //return HashedPassword with salted password as Hash and Salt
        }

        /// <summary>
        /// Generate salted Password
        /// </summary>
        /// <param name="password">Password</param>
        /// <param name="passwordSalt">Salt for mix with password</param>
        /// <returns>Salted password and salt</returns>
        private string GenerateSaltedPassword(string password, char[] passwordSalt)
        {
            List<char> saltedPassword = new List<char>();   //Initialize list for create Salted Password
            char[] passwordChars = password.ToCharArray();  //Transfer password string to Array

            for (int i = 0; passwordChars.Length >= i; i++) //Loop for mixing password and salt
            {
                saltedPassword.Add(passwordChars[i]);   //Add password char to salted password
                saltedPassword.Add(passwordSalt[i]);    //add salt char to salted password
            }

            return new string(saltedPassword.ToArray()); //Return string with saltedpassword
        }

        /// <summary>
        /// Generate salt 
        /// </summary>
        /// <param name="lenght">Number of salt chars</param>
        /// <returns>Salt</returns>
        private char[] GenerateSalt(int lenght)
        {
            List<char> salt = new List<char>(); //Create List for generate Salt string

            for (int i = lenght; i > 0; i--)    //Loop for generate requested lenght of salt
            {
                salt.Add(SaltChars[Random.Shared.Next(0, SaltChars.Length - 1)]);   //Random generate salt char
            }

            return salt.ToArray();  //return salt in array
        }

























    }
}