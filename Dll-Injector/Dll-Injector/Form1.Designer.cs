namespace Dll_Injector
{
    partial class Form1
    {
        /// <summary>
        /// Erforderliche Designervariable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Verwendete Ressourcen bereinigen.
        /// </summary>
        /// <param name="disposing">True, wenn verwaltete Ressourcen gelöscht werden sollen; andernfalls False.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Vom Windows Form-Designer generierter Code

        /// <summary>
        /// Erforderliche Methode für die Designerunterstützung.
        /// Der Inhalt der Methode darf nicht mit dem Code-Editor geändert werden.
        /// </summary>
        private void InitializeComponent()
        {
            this.btRefreshProcesses = new System.Windows.Forms.Button();
            this.clbProcesslist = new System.Windows.Forms.CheckedListBox();
            this.label1 = new System.Windows.Forms.Label();
            this.btRefreshDlls = new System.Windows.Forms.Button();
            this.btInject = new System.Windows.Forms.Button();
            this.label2 = new System.Windows.Forms.Label();
            this.tbSelectedDll = new System.Windows.Forms.TextBox();
            this.cbOnlyWindowed = new System.Windows.Forms.CheckBox();
            this.SuspendLayout();
            // 
            // btRefreshProcesses
            // 
            this.btRefreshProcesses.Location = new System.Drawing.Point(12, 385);
            this.btRefreshProcesses.Name = "btRefreshProcesses";
            this.btRefreshProcesses.Size = new System.Drawing.Size(340, 23);
            this.btRefreshProcesses.TabIndex = 1;
            this.btRefreshProcesses.Text = "Refresh";
            this.btRefreshProcesses.UseVisualStyleBackColor = true;
            this.btRefreshProcesses.Click += new System.EventHandler(this.btRefreshProcesses_Click);
            // 
            // clbProcesslist
            // 
            this.clbProcesslist.FormattingEnabled = true;
            this.clbProcesslist.Location = new System.Drawing.Point(12, 33);
            this.clbProcesslist.Name = "clbProcesslist";
            this.clbProcesslist.Size = new System.Drawing.Size(340, 319);
            this.clbProcesslist.TabIndex = 2;
            this.clbProcesslist.ItemCheck += new System.Windows.Forms.ItemCheckEventHandler(this.clbProcesslist_ItemCheck);
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Location = new System.Drawing.Point(151, 9);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(56, 13);
            this.label1.TabIndex = 4;
            this.label1.Text = "Processes";
            // 
            // btRefreshDlls
            // 
            this.btRefreshDlls.Location = new System.Drawing.Point(7, 456);
            this.btRefreshDlls.Name = "btRefreshDlls";
            this.btRefreshDlls.Size = new System.Drawing.Size(344, 23);
            this.btRefreshDlls.TabIndex = 5;
            this.btRefreshDlls.Text = "Select Dll";
            this.btRefreshDlls.UseVisualStyleBackColor = true;
            this.btRefreshDlls.Click += new System.EventHandler(this.btSelectDll_Click);
            // 
            // btInject
            // 
            this.btInject.Location = new System.Drawing.Point(7, 520);
            this.btInject.Name = "btInject";
            this.btInject.Size = new System.Drawing.Size(344, 23);
            this.btInject.TabIndex = 6;
            this.btInject.Text = "Inject";
            this.btInject.UseVisualStyleBackColor = true;
            this.btInject.Click += new System.EventHandler(this.btInject_Click);
            // 
            // label2
            // 
            this.label2.AutoSize = true;
            this.label2.Location = new System.Drawing.Point(168, 432);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(19, 13);
            this.label2.TabIndex = 7;
            this.label2.Text = "Dll";
            // 
            // tbSelectedDll
            // 
            this.tbSelectedDll.Location = new System.Drawing.Point(7, 485);
            this.tbSelectedDll.Name = "tbSelectedDll";
            this.tbSelectedDll.ReadOnly = true;
            this.tbSelectedDll.Size = new System.Drawing.Size(344, 20);
            this.tbSelectedDll.TabIndex = 9;
            // 
            // cbOnlyWindowed
            // 
            this.cbOnlyWindowed.AutoSize = true;
            this.cbOnlyWindowed.Location = new System.Drawing.Point(12, 358);
            this.cbOnlyWindowed.Name = "cbOnlyWindowed";
            this.cbOnlyWindowed.Size = new System.Drawing.Size(160, 17);
            this.cbOnlyWindowed.TabIndex = 10;
            this.cbOnlyWindowed.Text = "only processes with window ";
            this.cbOnlyWindowed.UseVisualStyleBackColor = true;
            // 
            // Form1
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(363, 555);
            this.Controls.Add(this.cbOnlyWindowed);
            this.Controls.Add(this.tbSelectedDll);
            this.Controls.Add(this.label2);
            this.Controls.Add(this.btInject);
            this.Controls.Add(this.btRefreshDlls);
            this.Controls.Add(this.label1);
            this.Controls.Add(this.clbProcesslist);
            this.Controls.Add(this.btRefreshProcesses);
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedSingle;
            this.Name = "Form1";
            this.Text = "Dll Injector";
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion
        private System.Windows.Forms.Button btRefreshProcesses;
        private System.Windows.Forms.CheckedListBox clbProcesslist;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.Button btRefreshDlls;
        private System.Windows.Forms.Button btInject;
        private System.Windows.Forms.Label label2;
        private System.Windows.Forms.TextBox tbSelectedDll;
        private System.Windows.Forms.CheckBox cbOnlyWindowed;
    }
}

