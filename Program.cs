using System;
using System.Windows.Forms;

namespace WlanManager
{
    static class Program
    {
        /// <summary>
        /// The main entry point for the application.
        /// </summary>
        [STAThread]
        static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            if (Environment.OSVersion.Version < new Version(6, 1))
            {
                MessageBox.Show("本程序仅支持 Windows 7 及以上系统");
            }
            else
            {
                Application.Run(new MainForm());
            }
        }
    }
}
