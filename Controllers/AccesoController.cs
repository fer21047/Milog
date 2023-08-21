using System;
using System.Data.SqlClient;
using System.Data;
using System.Security.Cryptography;
using System.Text;
using System.Web.Mvc;
using R2login.Models;
using System.IO;

namespace R2login.Controllers
{
    public class AccesoController : Controller
    {
        static string cadena = "Data Source=LAPTOP-46MTDJSU;Initial Catalog=ACCESO;Integrated Security=true";
        static string claveEncriptacion = "TuClaveSecreta";  // Cambia esto por tu clave secreta de encriptación

        public ActionResult Login()
        {
            // Reiniciar el contador de intentos fallidos al cargar la página de inicio de sesión.
            Session["IntentosFallidos"] = 0;
            return View();
        }

        public ActionResult Registrar()
        {
            return View();
        }

        [HttpPost]
        public ActionResult Registrar(Usuario oUsuario)
        {
            bool registrado;
            string mensaje;

            if (oUsuario.Password == oUsuario.ConfirmarPassword)
            {
                oUsuario.Password = Encriptar(oUsuario.Password);
            }
            else
            {
                ViewData["Mensaje"] = "Las contraseñas no coinciden";
                return View();
            }

            using (SqlConnection cn = new SqlConnection(cadena))
            {
                SqlCommand cmd = new SqlCommand("Registrar_Usuario", cn);
                cmd.Parameters.AddWithValue("Correo", oUsuario.Correo);
                cmd.Parameters.AddWithValue("Password", oUsuario.Password);
                cmd.Parameters.Add("Registrado", SqlDbType.Bit).Direction = ParameterDirection.Output;
                cmd.Parameters.Add("Mensaje", SqlDbType.VarChar, 100).Direction = ParameterDirection.Output;
                cmd.CommandType = CommandType.StoredProcedure;

                cn.Open();
                cmd.ExecuteNonQuery();
                registrado = Convert.ToBoolean(cmd.Parameters["Registrado"].Value);
                mensaje = cmd.Parameters["Mensaje"].Value.ToString();
            }

            ViewData["Mensaje"] = mensaje;

            if (registrado)
            {
                return RedirectToAction("Login", "Acceso");
            }
            else
            {
                return View();
            }
        }

        [HttpPost]
        public ActionResult Login(Usuario oUsuario)
        {
            oUsuario.Password = Encriptar(oUsuario.Password);

            using (SqlConnection cn = new SqlConnection(cadena))
            {
                bool usuarioValido = UsuarioYContraseñaSonValidos(oUsuario.Correo, oUsuario.Password);

                if (!usuarioValido)
                {
                    if (Session["IntentosFallidos"] == null)
                    {
                        Session["IntentosFallidos"] = 1;
                    }
                    else
                    {
                        Session["IntentosFallidos"] = (int)Session["IntentosFallidos"] + 1;
                    }
                }
                else
                {
                    Session["IntentosFallidos"] = 0;
                }

                SqlCommand cmd = new SqlCommand("Validar_Usuario", cn);
                cmd.Parameters.AddWithValue("Correo", oUsuario.Correo);
                cmd.Parameters.AddWithValue("Password", oUsuario.Password);
                cmd.CommandType = CommandType.StoredProcedure;

                cn.Open();
                oUsuario.ID = Convert.ToInt32(cmd.ExecuteScalar().ToString());
            }

            if (oUsuario.ID != 0)
            {
                Session["usuario"] = oUsuario;
                return RedirectToAction("Index", "Home");
            }
            else
            {
                ViewData["Mensaje"] = "Usuario no encontrado";
                return View();
            }
        }

        private string Encriptar(string texto)
        {
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Encoding.UTF8.GetBytes(claveEncriptacion);
                aesAlg.IV = new byte[16]; // Vector de inicialización
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(texto);
                        }
                    }
                    return Convert.ToBase64String(msEncrypt.ToArray());
                }
            }
        }

        private string Desencriptar(string textoEncriptado)
        {
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Encoding.UTF8.GetBytes(claveEncriptacion);
                aesAlg.IV = new byte[16]; // Vector de inicialización
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msDecrypt = new MemoryStream(Convert.FromBase64String(textoEncriptado)))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            return srDecrypt.ReadToEnd();
                        }
                    }
                }
            }
        }

        private bool UsuarioYContraseñaSonValidos(string correo, string contraseña)
        {
            bool usuarioValido = false;

            using (SqlConnection cn = new SqlConnection(cadena))
            {
                cn.Open();

                string consulta = "SELECT COUNT(*) FROM Usuario WHERE Correo = @Correo AND Password = @Password";
                using (SqlCommand cmd = new SqlCommand(consulta, cn))
                {
                    cmd.Parameters.AddWithValue("@Correo", correo);
                    cmd.Parameters.AddWithValue("@Password", Encriptar(contraseña));

                    int count = Convert.ToInt32(cmd.ExecuteScalar());
                    usuarioValido = count > 0;
                }
            }

            return usuarioValido;
        }
    }
}



