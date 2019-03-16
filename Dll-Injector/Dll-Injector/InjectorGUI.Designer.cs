namespace Dll_Injector
{
    partial class Injector
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
            this.label1 = new System.Windows.Forms.Label();
            this.btRefreshDlls = new System.Windows.Forms.Button();
            this.btInject = new System.Windows.Forms.Button();
            this.label2 = new System.Windows.Forms.Label();
            this.tbSelectedDll = new System.Windows.Forms.TextBox();
            this.cbOnlyWindowed = new System.Windows.Forms.CheckBox();
            this.lvProcessList = new System.Windows.Forms.ListView();
            this.tbDllArchitecture = new System.Windows.Forms.TextBox();
            this.button1 = new System.Windows.Forms.Button();
            this.rbLoadLibrary = new System.Windows.Forms.RadioButton();
            this.rbReflective = new System.Windows.Forms.RadioButton();
            this.lbInjectionreturn = new System.Windows.Forms.Label();
            this.gbInjectionOptions = new System.Windows.Forms.GroupBox();
            this.tbLoadFnName = new System.Windows.Forms.TextBox();
            this.lbLoadFnName = new System.Windows.Forms.Label();
            this.gbInjectionOptions.SuspendLayout();
            this.SuspendLayout();
            // 
            // btRefreshProcesses
            // 
            this.btRefreshProcesses.Location = new System.Drawing.Point(232, 406);
            this.btRefreshProcesses.Name = "btRefreshProcesses";
            this.btRefreshProcesses.Size = new System.Drawing.Size(197, 23);
            this.btRefreshProcesses.TabIndex = 1;
            this.btRefreshProcesses.Text = "Refresh";
            this.btRefreshProcesses.UseVisualStyleBackColor = true;
            this.btRefreshProcesses.Click += new System.EventHandler(this.btRefreshProcesses_Click);
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
            this.btRefreshDlls.Location = new System.Drawing.Point(446, 25);
            this.btRefreshDlls.Name = "btRefreshDlls";
            this.btRefreshDlls.Size = new System.Drawing.Size(344, 23);
            this.btRefreshDlls.TabIndex = 5;
            this.btRefreshDlls.Text = "Select Dll";
            this.btRefreshDlls.UseVisualStyleBackColor = true;
            this.btRefreshDlls.Click += new System.EventHandler(this.btSelectDll_Click);
            // 
            // btInject
            // 
            this.btInject.Location = new System.Drawing.Point(446, 367);
            this.btInject.Name = "btInject";
            this.btInject.Size = new System.Drawing.Size(180, 23);
            this.btInject.TabIndex = 6;
            this.btInject.Text = "Inject";
            this.btInject.UseVisualStyleBackColor = true;
            this.btInject.Click += new System.EventHandler(this.btInject_Click);
            // 
            // label2
            // 
            this.label2.AutoSize = true;
            this.label2.Location = new System.Drawing.Point(607, 1);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(19, 13);
            this.label2.TabIndex = 7;
            this.label2.Text = "Dll";
            // 
            // tbSelectedDll
            // 
            this.tbSelectedDll.Location = new System.Drawing.Point(446, 54);
            this.tbSelectedDll.Name = "tbSelectedDll";
            this.tbSelectedDll.ReadOnly = true;
            this.tbSelectedDll.Size = new System.Drawing.Size(273, 20);
            this.tbSelectedDll.TabIndex = 9;
            // 
            // cbOnlyWindowed
            // 
            this.cbOnlyWindowed.AutoSize = true;
            this.cbOnlyWindowed.Location = new System.Drawing.Point(22, 406);
            this.cbOnlyWindowed.Name = "cbOnlyWindowed";
            this.cbOnlyWindowed.Size = new System.Drawing.Size(160, 17);
            this.cbOnlyWindowed.TabIndex = 10;
            this.cbOnlyWindowed.Text = "only processes with window ";
            this.cbOnlyWindowed.UseVisualStyleBackColor = true;
            // 
            // lvProcessList
            // 
            this.lvProcessList.BorderStyle = System.Windows.Forms.BorderStyle.FixedSingle;
            this.lvProcessList.CheckBoxes = true;
            this.lvProcessList.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.5F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.lvProcessList.HeaderStyle = System.Windows.Forms.ColumnHeaderStyle.Nonclickable;
            this.lvProcessList.Location = new System.Drawing.Point(12, 25);
            this.lvProcessList.Name = "lvProcessList";
            this.lvProcessList.Size = new System.Drawing.Size(417, 375);
            this.lvProcessList.TabIndex = 11;
            this.lvProcessList.UseCompatibleStateImageBehavior = false;
            this.lvProcessList.View = System.Windows.Forms.View.Details;
            // 
            // tbDllArchitecture
            // 
            this.tbDllArchitecture.Location = new System.Drawing.Point(725, 54);
            this.tbDllArchitecture.Name = "tbDllArchitecture";
            this.tbDllArchitecture.ReadOnly = true;
            this.tbDllArchitecture.Size = new System.Drawing.Size(64, 20);
            this.tbDllArchitecture.TabIndex = 12;
            // 
            // button1
            // 
            this.button1.Location = new System.Drawing.Point(715, 406);
            this.button1.Name = "button1";
            this.button1.Size = new System.Drawing.Size(75, 23);
            this.button1.TabIndex = 13;
            this.button1.Text = "Debug";
            this.button1.UseVisualStyleBackColor = true;
            this.button1.Click += new System.EventHandler(this.button1_Click);
            // 
            // rbLoadLibrary
            // 
            this.rbLoadLibrary.AutoSize = true;
            this.rbLoadLibrary.Location = new System.Drawing.Point(453, 94);
            this.rbLoadLibrary.Name = "rbLoadLibrary";
            this.rbLoadLibrary.Size = new System.Drawing.Size(80, 17);
            this.rbLoadLibrary.TabIndex = 14;
            this.rbLoadLibrary.TabStop = true;
            this.rbLoadLibrary.Text = "LoadLibrary";
            this.rbLoadLibrary.UseVisualStyleBackColor = true;
            this.rbLoadLibrary.CheckedChanged += new System.EventHandler(this.rbLoadLibrary_CheckedChanged);
            // 
            // rbReflective
            // 
            this.rbReflective.AutoSize = true;
            this.rbReflective.Location = new System.Drawing.Point(541, 94);
            this.rbReflective.Name = "rbReflective";
            this.rbReflective.Size = new System.Drawing.Size(73, 17);
            this.rbReflective.TabIndex = 16;
            this.rbReflective.TabStop = true;
            this.rbReflective.Text = "Reflective";
            this.rbReflective.UseVisualStyleBackColor = true;
            this.rbReflective.CheckedChanged += new System.EventHandler(this.rbReflective_CheckedChanged);
            // 
            // lbInjectionreturn
            // 
            this.lbInjectionreturn.AutoSize = true;
            this.lbInjectionreturn.Location = new System.Drawing.Point(655, 372);
            this.lbInjectionreturn.Name = "lbInjectionreturn";
            this.lbInjectionreturn.Size = new System.Drawing.Size(73, 13);
            this.lbInjectionreturn.TabIndex = 18;
            this.lbInjectionreturn.Text = "injectionreturn";
            // 
            // gbInjectionOptions
            // 
            this.gbInjectionOptions.Controls.Add(this.lbLoadFnName);
            this.gbInjectionOptions.Controls.Add(this.tbLoadFnName);
            this.gbInjectionOptions.Location = new System.Drawing.Point(453, 127);
            this.gbInjectionOptions.Name = "gbInjectionOptions";
            this.gbInjectionOptions.Size = new System.Drawing.Size(336, 216);
            this.gbInjectionOptions.TabIndex = 19;
            this.gbInjectionOptions.TabStop = false;
            // 
            // tbLoadFnName
            // 
            this.tbLoadFnName.Location = new System.Drawing.Point(9, 32);
            this.tbLoadFnName.Name = "tbLoadFnName";
            this.tbLoadFnName.Size = new System.Drawing.Size(321, 20);
            this.tbLoadFnName.TabIndex = 0;
            this.tbLoadFnName.Text = "ReflectiveLoader";
            // 
            // lbLoadFnName
            // 
            this.lbLoadFnName.AutoSize = true;
            this.lbLoadFnName.Location = new System.Drawing.Point(6, 16);
            this.lbLoadFnName.Name = "lbLoadFnName";
            this.lbLoadFnName.Size = new System.Drawing.Size(109, 13);
            this.lbLoadFnName.TabIndex = 1;
            this.lbLoadFnName.Text = "Load Function Name:";
            // 
            // Injector
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(807, 449);
            this.Controls.Add(this.gbInjectionOptions);
            this.Controls.Add(this.lbInjectionreturn);
            this.Controls.Add(this.rbReflective);
            this.Controls.Add(this.rbLoadLibrary);
            this.Controls.Add(this.button1);
            this.Controls.Add(this.tbDllArchitecture);
            this.Controls.Add(this.lvProcessList);
            this.Controls.Add(this.cbOnlyWindowed);
            this.Controls.Add(this.tbSelectedDll);
            this.Controls.Add(this.label2);
            this.Controls.Add(this.btInject);
            this.Controls.Add(this.btRefreshDlls);
            this.Controls.Add(this.label1);
            this.Controls.Add(this.btRefreshProcesses);
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedSingle;
            this.Name = "Injector";
            this.Text = "Dll Injector";
            this.gbInjectionOptions.ResumeLayout(false);
            this.gbInjectionOptions.PerformLayout();
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion
        private System.Windows.Forms.Button btRefreshProcesses;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.Button btRefreshDlls;
        private System.Windows.Forms.Button btInject;
        private System.Windows.Forms.Label label2;
        private System.Windows.Forms.TextBox tbSelectedDll;
        private System.Windows.Forms.CheckBox cbOnlyWindowed;
        private System.Windows.Forms.ListView lvProcessList;
        private System.Windows.Forms.TextBox tbDllArchitecture;
        private System.Windows.Forms.Button button1;
        private System.Windows.Forms.RadioButton rbLoadLibrary;
        private System.Windows.Forms.RadioButton rbReflective;
        private System.Windows.Forms.Label lbInjectionreturn;
        private System.Windows.Forms.GroupBox gbInjectionOptions;
        private System.Windows.Forms.Label lbLoadFnName;
        private System.Windows.Forms.TextBox tbLoadFnName;
    }
}

