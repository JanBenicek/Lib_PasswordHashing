using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Lib_PasswordHashing
{
    public class HashedPassword
    {
        public string Salt { get; set; }
        public string Hash { get; set; }
    }
}
