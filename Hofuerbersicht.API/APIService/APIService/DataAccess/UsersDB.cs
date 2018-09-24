using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace APIService.DataAccess
{
    public class UsersDB : DbContext
    {
        public UsersDB(DbContextOptions<UsersDB> options) : base(options) { }

        public DbSet<Users> Users { get; set; }
    }
}
