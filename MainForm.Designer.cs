namespace WlanManager
{
    partial class MainForm
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.button1 = new System.Windows.Forms.Button();
            this.button2 = new System.Windows.Forms.Button();
            this.stateGroupBox = new System.Windows.Forms.GroupBox();
            this.infoGroupBox = new System.Windows.Forms.GroupBox();
            this.button3 = new System.Windows.Forms.Button();
            this.modeLabel = new System.Windows.Forms.Label();
            this.label5 = new System.Windows.Forms.Label();
            this.encLabel = new System.Windows.Forms.Label();
            this.authLabel = new System.Windows.Forms.Label();
            this.maxLabel = new System.Windows.Forms.Label();
            this.ssidLabel = new System.Windows.Forms.Label();
            this.label4 = new System.Windows.Forms.Label();
            this.label3 = new System.Windows.Forms.Label();
            this.label2 = new System.Windows.Forms.Label();
            this.label1 = new System.Windows.Forms.Label();
            this.label6 = new System.Windows.Forms.Label();
            this.label7 = new System.Windows.Forms.Label();
            this.label8 = new System.Windows.Forms.Label();
            this.statusLabel = new System.Windows.Forms.Label();
            this.bssidLabel = new System.Windows.Forms.Label();
            this.chLabel = new System.Windows.Forms.Label();
            this.label9 = new System.Windows.Forms.Label();
            this.numLabel = new System.Windows.Forms.Label();
            this.stateGroupBox.SuspendLayout();
            this.infoGroupBox.SuspendLayout();
            this.SuspendLayout();
            // 
            // button1
            // 
            this.button1.Location = new System.Drawing.Point(179, 20);
            this.button1.Name = "button1";
            this.button1.Size = new System.Drawing.Size(75, 23);
            this.button1.TabIndex = 0;
            this.button1.Text = "启动";
            this.button1.UseVisualStyleBackColor = true;
            this.button1.Click += new System.EventHandler(this.button1_Click);
            // 
            // button2
            // 
            this.button2.Location = new System.Drawing.Point(179, 49);
            this.button2.Name = "button2";
            this.button2.Size = new System.Drawing.Size(75, 23);
            this.button2.TabIndex = 1;
            this.button2.Text = "停止";
            this.button2.UseVisualStyleBackColor = true;
            this.button2.Click += new System.EventHandler(this.button2_Click);
            // 
            // stateGroupBox
            // 
            this.stateGroupBox.Controls.Add(this.numLabel);
            this.stateGroupBox.Controls.Add(this.label9);
            this.stateGroupBox.Controls.Add(this.chLabel);
            this.stateGroupBox.Controls.Add(this.bssidLabel);
            this.stateGroupBox.Controls.Add(this.statusLabel);
            this.stateGroupBox.Controls.Add(this.label8);
            this.stateGroupBox.Controls.Add(this.label7);
            this.stateGroupBox.Controls.Add(this.label6);
            this.stateGroupBox.Controls.Add(this.button1);
            this.stateGroupBox.Controls.Add(this.button2);
            this.stateGroupBox.Location = new System.Drawing.Point(12, 126);
            this.stateGroupBox.Name = "stateGroupBox";
            this.stateGroupBox.Size = new System.Drawing.Size(260, 124);
            this.stateGroupBox.TabIndex = 4;
            this.stateGroupBox.TabStop = false;
            this.stateGroupBox.Text = "承载网络状态";
            // 
            // infoGroupBox
            // 
            this.infoGroupBox.Controls.Add(this.button3);
            this.infoGroupBox.Controls.Add(this.modeLabel);
            this.infoGroupBox.Controls.Add(this.label5);
            this.infoGroupBox.Controls.Add(this.encLabel);
            this.infoGroupBox.Controls.Add(this.authLabel);
            this.infoGroupBox.Controls.Add(this.maxLabel);
            this.infoGroupBox.Controls.Add(this.ssidLabel);
            this.infoGroupBox.Controls.Add(this.label4);
            this.infoGroupBox.Controls.Add(this.label3);
            this.infoGroupBox.Controls.Add(this.label2);
            this.infoGroupBox.Controls.Add(this.label1);
            this.infoGroupBox.Location = new System.Drawing.Point(12, 12);
            this.infoGroupBox.Name = "infoGroupBox";
            this.infoGroupBox.Size = new System.Drawing.Size(260, 100);
            this.infoGroupBox.TabIndex = 6;
            this.infoGroupBox.TabStop = false;
            this.infoGroupBox.Text = "承载网络设置";
            // 
            // button3
            // 
            this.button3.Location = new System.Drawing.Point(179, 12);
            this.button3.Name = "button3";
            this.button3.Size = new System.Drawing.Size(75, 23);
            this.button3.TabIndex = 16;
            this.button3.Text = "配置";
            this.button3.UseVisualStyleBackColor = true;
            this.button3.Click += new System.EventHandler(this.button3_Click);
            // 
            // modeLabel
            // 
            this.modeLabel.AutoSize = true;
            this.modeLabel.Location = new System.Drawing.Point(49, 23);
            this.modeLabel.Name = "modeLabel";
            this.modeLabel.Size = new System.Drawing.Size(0, 12);
            this.modeLabel.TabIndex = 15;
            // 
            // label5
            // 
            this.label5.AutoSize = true;
            this.label5.Location = new System.Drawing.Point(8, 23);
            this.label5.Name = "label5";
            this.label5.Size = new System.Drawing.Size(35, 12);
            this.label5.TabIndex = 14;
            this.label5.Text = "模式:";
            // 
            // encLabel
            // 
            this.encLabel.AutoSize = true;
            this.encLabel.Location = new System.Drawing.Point(173, 65);
            this.encLabel.Name = "encLabel";
            this.encLabel.Size = new System.Drawing.Size(0, 12);
            this.encLabel.TabIndex = 13;
            // 
            // authLabel
            // 
            this.authLabel.AutoSize = true;
            this.authLabel.Location = new System.Drawing.Point(196, 44);
            this.authLabel.Name = "authLabel";
            this.authLabel.Size = new System.Drawing.Size(0, 12);
            this.authLabel.TabIndex = 12;
            // 
            // maxLabel
            // 
            this.maxLabel.AutoSize = true;
            this.maxLabel.Location = new System.Drawing.Point(98, 65);
            this.maxLabel.Name = "maxLabel";
            this.maxLabel.Size = new System.Drawing.Size(0, 12);
            this.maxLabel.TabIndex = 11;
            // 
            // ssidLabel
            // 
            this.ssidLabel.AutoSize = true;
            this.ssidLabel.Location = new System.Drawing.Point(50, 44);
            this.ssidLabel.Name = "ssidLabel";
            this.ssidLabel.Size = new System.Drawing.Size(0, 12);
            this.ssidLabel.TabIndex = 10;
            // 
            // label4
            // 
            this.label4.AutoSize = true;
            this.label4.Location = new System.Drawing.Point(132, 65);
            this.label4.Name = "label4";
            this.label4.Size = new System.Drawing.Size(35, 12);
            this.label4.TabIndex = 9;
            this.label4.Text = "加密:";
            // 
            // label3
            // 
            this.label3.AutoSize = true;
            this.label3.Location = new System.Drawing.Point(131, 44);
            this.label3.Name = "label3";
            this.label3.Size = new System.Drawing.Size(59, 12);
            this.label3.TabIndex = 8;
            this.label3.Text = "身份验证:";
            // 
            // label2
            // 
            this.label2.AutoSize = true;
            this.label2.Location = new System.Drawing.Point(9, 65);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(83, 12);
            this.label2.TabIndex = 7;
            this.label2.Text = "最多客户端数:";
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Location = new System.Drawing.Point(9, 44);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(35, 12);
            this.label1.TabIndex = 6;
            this.label1.Text = "SSID:";
            // 
            // label6
            // 
            this.label6.AutoSize = true;
            this.label6.Location = new System.Drawing.Point(21, 25);
            this.label6.Name = "label6";
            this.label6.Size = new System.Drawing.Size(35, 12);
            this.label6.TabIndex = 2;
            this.label6.Text = "状态:";
            // 
            // label7
            // 
            this.label7.AutoSize = true;
            this.label7.Location = new System.Drawing.Point(15, 49);
            this.label7.Name = "label7";
            this.label7.Size = new System.Drawing.Size(41, 12);
            this.label7.TabIndex = 3;
            this.label7.Text = "BSSID:";
            // 
            // label8
            // 
            this.label8.AutoSize = true;
            this.label8.Location = new System.Drawing.Point(22, 75);
            this.label8.Name = "label8";
            this.label8.Size = new System.Drawing.Size(35, 12);
            this.label8.TabIndex = 4;
            this.label8.Text = "频道:";
            // 
            // statusLabel
            // 
            this.statusLabel.AutoSize = true;
            this.statusLabel.Location = new System.Drawing.Point(63, 25);
            this.statusLabel.Name = "statusLabel";
            this.statusLabel.Size = new System.Drawing.Size(0, 12);
            this.statusLabel.TabIndex = 5;
            // 
            // bssidLabel
            // 
            this.bssidLabel.AutoSize = true;
            this.bssidLabel.Location = new System.Drawing.Point(63, 49);
            this.bssidLabel.Name = "bssidLabel";
            this.bssidLabel.Size = new System.Drawing.Size(0, 12);
            this.bssidLabel.TabIndex = 6;
            // 
            // chLabel
            // 
            this.chLabel.AutoSize = true;
            this.chLabel.Location = new System.Drawing.Point(63, 75);
            this.chLabel.Name = "chLabel";
            this.chLabel.Size = new System.Drawing.Size(0, 12);
            this.chLabel.TabIndex = 7;
            // 
            // label9
            // 
            this.label9.AutoSize = true;
            this.label9.Location = new System.Drawing.Point(9, 97);
            this.label9.Name = "label9";
            this.label9.Size = new System.Drawing.Size(47, 12);
            this.label9.TabIndex = 8;
            this.label9.Text = "连接数:";
            // 
            // numLabel
            // 
            this.numLabel.AutoSize = true;
            this.numLabel.Location = new System.Drawing.Point(63, 97);
            this.numLabel.Name = "numLabel";
            this.numLabel.Size = new System.Drawing.Size(0, 12);
            this.numLabel.TabIndex = 9;
            // 
            // MainForm
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 12F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(284, 262);
            this.Controls.Add(this.infoGroupBox);
            this.Controls.Add(this.stateGroupBox);
            this.Name = "MainForm";
            this.Text = "承载网络管理器";
            this.Load += new System.EventHandler(this.Form1_Load);
            this.stateGroupBox.ResumeLayout(false);
            this.stateGroupBox.PerformLayout();
            this.infoGroupBox.ResumeLayout(false);
            this.infoGroupBox.PerformLayout();
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.Button button1;
        private System.Windows.Forms.Button button2;
        private System.Windows.Forms.GroupBox stateGroupBox;
        private System.Windows.Forms.GroupBox infoGroupBox;
        private System.Windows.Forms.Label ssidLabel;
        private System.Windows.Forms.Label label4;
        private System.Windows.Forms.Label label3;
        private System.Windows.Forms.Label label2;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.Label maxLabel;
        private System.Windows.Forms.Label authLabel;
        private System.Windows.Forms.Label encLabel;
        private System.Windows.Forms.Label modeLabel;
        private System.Windows.Forms.Label label5;
        private System.Windows.Forms.Button button3;
        private System.Windows.Forms.Label numLabel;
        private System.Windows.Forms.Label label9;
        private System.Windows.Forms.Label chLabel;
        private System.Windows.Forms.Label bssidLabel;
        private System.Windows.Forms.Label statusLabel;
        private System.Windows.Forms.Label label8;
        private System.Windows.Forms.Label label7;
        private System.Windows.Forms.Label label6;
    }
}

