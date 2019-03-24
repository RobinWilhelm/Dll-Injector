namespace Dll_Injector.MethodGUIs
{
    partial class ReflectivInjectionGUI
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
            this.control = new System.Windows.Forms.GroupBox();
            this.tbLoadFnName = new System.Windows.Forms.TextBox();
            this.rbUseShellcode = new System.Windows.Forms.RadioButton();
            this.rbUseExportedFunction = new System.Windows.Forms.RadioButton();
            this.control.SuspendLayout();
            this.SuspendLayout();
            // 
            // control
            // 
            this.control.Controls.Add(this.tbLoadFnName);
            this.control.Controls.Add(this.rbUseShellcode);
            this.control.Controls.Add(this.rbUseExportedFunction);
            this.control.Location = new System.Drawing.Point(57, 49);
            this.control.Name = "control";
            this.control.Size = new System.Drawing.Size(336, 216);
            this.control.TabIndex = 20;
            this.control.TabStop = false;
            // 
            // tbLoadFnName
            // 
            this.tbLoadFnName.Location = new System.Drawing.Point(6, 43);
            this.tbLoadFnName.Name = "tbLoadFnName";
            this.tbLoadFnName.Size = new System.Drawing.Size(324, 20);
            this.tbLoadFnName.TabIndex = 2;
            this.tbLoadFnName.Text = "Function Name";
            // 
            // rbUseShellcode
            // 
            this.rbUseShellcode.AutoSize = true;
            this.rbUseShellcode.Location = new System.Drawing.Point(7, 85);
            this.rbUseShellcode.Name = "rbUseShellcode";
            this.rbUseShellcode.Size = new System.Drawing.Size(94, 17);
            this.rbUseShellcode.TabIndex = 1;
            this.rbUseShellcode.TabStop = true;
            this.rbUseShellcode.Text = "Use Shellcode";
            this.rbUseShellcode.UseVisualStyleBackColor = true;
            // 
            // rbUseExportedFunction
            // 
            this.rbUseExportedFunction.AutoSize = true;
            this.rbUseExportedFunction.Location = new System.Drawing.Point(6, 19);
            this.rbUseExportedFunction.Name = "rbUseExportedFunction";
            this.rbUseExportedFunction.Size = new System.Drawing.Size(160, 17);
            this.rbUseExportedFunction.TabIndex = 0;
            this.rbUseExportedFunction.TabStop = true;
            this.rbUseExportedFunction.Text = "Use Exported Load Function";
            this.rbUseExportedFunction.UseVisualStyleBackColor = true;
            // 
            // ReflectivInjectionGUI
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(450, 314);
            this.Controls.Add(this.control);
            this.Name = "ReflectivInjectionGUI";
            this.Text = "Form1";
            this.control.ResumeLayout(false);
            this.control.PerformLayout();
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.GroupBox control;
        private System.Windows.Forms.TextBox tbLoadFnName;
        private System.Windows.Forms.RadioButton rbUseShellcode;
        private System.Windows.Forms.RadioButton rbUseExportedFunction;
    }
}