using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace APIService.DataAccess
{
    public class Users
    {
        public int id { get; set; }
        public string username { get; set; }
        public string password { get; set; }
        public DateTime lastLogon { get; set; }
        public string refreshToken { get; set; }
    }
}
