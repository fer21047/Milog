using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace R2login.Models
{
    public class Usuario
    {
        public int ID { get; set; }
        public string Correo { get; set; }
        public string Password { get; set; }


        public string ConfirmarPassword { get; set; }

    }
}