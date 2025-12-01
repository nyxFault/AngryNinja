from binaryninja import (
    PluginCommand, 
    show_message_box, 
    MessageBoxButtonSet, 
    MessageBoxIcon,
    log_info,
    BackgroundTaskThread
)

from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, 
    QApplication, QTextEdit, QLineEdit, QSpinBox, QProgressBar,
    QGroupBox, QFormLayout, QCheckBox, QComboBox
)
from PySide6.QtCore import Qt, QTimer

# Global reference to keep the dialog alive
_angr_dialog = None

# Try to import angr, but don't fail if not available
ANGR_AVAILABLE = False
try:
    import angr
    import claripy
    ANGR_AVAILABLE = True
    log_info("angr successfully imported")
except ImportError:
    log_info("angr not available")

class AngrSolverTask(BackgroundTaskThread):
    def __init__(self, bv, target_string, avoid_string, input_size, input_method="argv", 
                 constraint_options=None, stdin_type="symbolic_bytes"):
        super().__init__("Solving with angr...", True)
        self.bv = bv
        self.target_string = target_string
        self.avoid_string = avoid_string
        self.input_size = input_size
        self.input_method = input_method
        self.stdin_type = stdin_type
        self.constraint_options = constraint_options or {}
        self.result = None
        self.error = None
        self._progress_text = "Starting..."
        self._finished = False
        
    def run(self):
        if not ANGR_AVAILABLE:
            self.error = "angr is not installed in Binary Ninja's Python environment"
            self._finished = True
            return
            
        try:
            binary_path = self.bv.file.original_filename
            log_info(f"Starting angr analysis on: {binary_path}")
            
            project = angr.Project(binary_path, auto_load_libs=False)
            
            if self.input_method == "argv":
                user_input, initial_state = self._setup_argv_input(project)
            else:
                user_input, initial_state = self._setup_stdin_input(project)
            
            if self.constraint_options.get('zero_fill_memory', False):
                initial_state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
            if self.constraint_options.get('zero_fill_registers', False):
                initial_state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)
            
            self._apply_char_constraints(initial_state, user_input)
            
            simgr = project.factory.simulation_manager(initial_state)
            
            self._progress_text = "Exploring paths..."
            
            simgr.explore(
                find=lambda s: self.target_string.encode() in s.posix.dumps(1) if self.target_string else False,
                avoid=lambda s: self.avoid_string.encode() in s.posix.dumps(1) if self.avoid_string else False
            )
            
            if simgr.found:
                found_state = simgr.found[0]
                
                if self.input_method == "argv":
                    solution = found_state.solver.eval(user_input, cast_to=bytes)
                else:
                    solution = found_state.solver.eval(user_input, cast_to=bytes)
                
                self.result = self._clean_solution(solution)
                    
                self._progress_text = f"Solution found"
                log_info(f"angr found solution: {self.result}")
            else:
                self.result = None
                self._progress_text = "No solution found"
                log_info("angr found no solution")
                
        except Exception as e:
            self.error = str(e)
            log_info(f"Angr solver error: {e}")
        
        self._finished = True
    
    def _setup_argv_input(self, project):
        user_input = claripy.BVS('user_input', self.input_size * 8)
        
        initial_state = project.factory.full_init_state(
            args=[project.filename, user_input],
            add_options={
                angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
            }
        )
        return user_input, initial_state
    
    def _setup_stdin_input(self, project):
        if self.stdin_type == "symbolic_bytes":
            user_input = claripy.BVS('stdin_input', self.input_size * 8)
            initial_state = project.factory.entry_state(
                stdin=user_input,
                add_options={
                    angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
                }
            )
        else:
            bytes_syms = [claripy.BVS(f"stdin_byte_{i}", 8) for i in range(self.input_size)]
            user_input = claripy.Concat(*bytes_syms)
            
            simfile = angr.SimFile("/dev/stdin", content=user_input, size=self.input_size)
            
            initial_state = project.factory.entry_state(
                args=[project.filename],
                stdin=simfile,
                add_options={
                    angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
                }
            )
        
        return user_input, initial_state
    
    def _apply_char_constraints(self, state, symbolic_input):
        constraints = []
        
        uppercase = self.constraint_options.get('uppercase', False)
        lowercase = self.constraint_options.get('lowercase', False)
        digits = self.constraint_options.get('digits', False)
        printable = self.constraint_options.get('printable', False)
        allow_null = self.constraint_options.get('allow_null', True)
        allow_newline = self.constraint_options.get('allow_newline', False)
        
        for i in range(self.input_size):
            byte_val = symbolic_input.get_byte(i)
            byte_constraints = []
            
            if uppercase:
                byte_constraints.append(claripy.And(byte_val >= ord('A'), byte_val <= ord('Z')))
            if lowercase:
                byte_constraints.append(claripy.And(byte_val >= ord('a'), byte_val <= ord('z')))
            if digits:
                byte_constraints.append(claripy.And(byte_val >= ord('0'), byte_val <= ord('9')))
            if printable:
                byte_constraints.append(claripy.And(byte_val >= 0x20, byte_val <= 0x7e))
            if allow_null:
                byte_constraints.append(byte_val == 0)
            if allow_newline:
                byte_constraints.append(byte_val == ord('\n'))
            
            if byte_constraints:
                if len(byte_constraints) == 1:
                    constraints.append(byte_constraints[0])
                else:
                    constraints.append(claripy.Or(*byte_constraints))
        
        for constraint in constraints:
            state.solver.add(constraint)
    
    def _clean_solution(self, solution):
        try:
            if self.input_method == "argv":
                clean_solution = solution.split(b'\x00')[0] if b'\x00' in solution else solution
                return clean_solution.decode('utf-8', errors='ignore')
            else:
                if b'\x00' in solution or b'\n' in solution:
                    clean_bytes = solution.split(b'\x00')[0].split(b'\n')[0]
                    return clean_bytes.decode('utf-8', errors='ignore')
                else:
                    return solution.decode('utf-8', errors='ignore')
        except:
            return str(solution)
    
    def get_progress(self):
        return self._progress_text
    
    def is_finished(self):
        return self._finished

class AngrSolverDialog(QDialog):
    def __init__(self, bv, parent=None):
        super().__init__(parent)
        self.bv = bv
        self.solver_task = None
        self.progress_timer = None
        self.init_ui()
        
    def init_ui(self):
        self.setWindowTitle("angr Symbolic Execution Solver")
        self.setMinimumSize(650, 600)
        
        layout = QVBoxLayout()
        
        title = QLabel("angr Symbolic Execution Configuration")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("font-size: 16px; font-weight: bold; margin: 10px;")
        layout.addWidget(title)
        
        if not ANGR_AVAILABLE:
            warning_label = QLabel("⚠️ angr is not installed. Please install it via: pip install angr")
            warning_label.setStyleSheet("color: red; font-weight: bold; padding: 10px;")
            warning_label.setWordWrap(True)
            layout.addWidget(warning_label)
        
        config_group = QGroupBox("Solver Configuration")
        config_layout = QFormLayout()
        
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("e.g., Cracked!, Success, Welcome")
        config_layout.addRow("Target String (find):", self.target_input)
        
        self.avoid_input = QLineEdit()
        self.avoid_input.setPlaceholderText("e.g., Try Again!, Failed, Error")
        config_layout.addRow("Avoid String (avoid):", self.avoid_input)
        
        self.size_input = QSpinBox()
        self.size_input.setRange(1, 256)
        self.size_input.setValue(20)
        config_layout.addRow("Input Size:", self.size_input)
        
        self.input_method_combo = QComboBox()
        self.input_method_combo.addItem("Command Line Argument (argv)", "argv")
        self.input_method_combo.addItem("Standard Input (stdin)", "stdin")
        self.input_method_combo.currentIndexChanged.connect(self.on_input_method_changed)
        config_layout.addRow("Input Method:", self.input_method_combo)
        
        self.stdin_type_combo = QComboBox()
        self.stdin_type_combo.addItem("Symbolic Bytes", "symbolic_bytes")
        self.stdin_type_combo.addItem("SimFile (Advanced)", "simfile")
        config_layout.addRow("STDIN Type:", self.stdin_type_combo)
        self.stdin_type_combo.setVisible(False)
        
        config_group.setLayout(config_layout)
        layout.addWidget(config_group)
        
        constraints_group = QGroupBox("Character Constraints")
        constraints_layout = QVBoxLayout()
        
        zero_fill_layout = QHBoxLayout()
        self.zero_memory_checkbox = QCheckBox("Zero fill unconstrained memory")
        zero_fill_layout.addWidget(self.zero_memory_checkbox)
        
        self.zero_registers_checkbox = QCheckBox("Zero fill unconstrained registers")
        zero_fill_layout.addWidget(self.zero_registers_checkbox)
        
        constraints_layout.addLayout(zero_fill_layout)
        
        char_constraints_layout = QFormLayout()
        
        self.uppercase_checkbox = QCheckBox("A-Z")
        char_constraints_layout.addRow("Uppercase letters:", self.uppercase_checkbox)
        
        self.lowercase_checkbox = QCheckBox("a-z")
        char_constraints_layout.addRow("Lowercase letters:", self.lowercase_checkbox)
        
        self.digits_checkbox = QCheckBox("0-9")
        char_constraints_layout.addRow("Digits:", self.digits_checkbox)
        
        self.printable_checkbox = QCheckBox("Printable ASCII (0x20-0x7e)")
        self.printable_checkbox.setChecked(True)
        char_constraints_layout.addRow("Printable ASCII:", self.printable_checkbox)
        
        self.null_checkbox = QCheckBox("Allow NULL bytes")
        self.null_checkbox.setChecked(True)
        char_constraints_layout.addRow("NULL bytes:", self.null_checkbox)
        
        self.newline_checkbox = QCheckBox("Allow newline (\\n)")
        char_constraints_layout.addRow("Newline:", self.newline_checkbox)
        
        constraints_layout.addLayout(char_constraints_layout)
        
        info_label = QLabel("Note: Multiple constraints are combined with OR. Leaving all unchecked allows any byte value.")
        info_label.setStyleSheet("color: gray; font-size: 10px;")
        info_label.setWordWrap(True)
        constraints_layout.addWidget(info_label)
        
        constraints_group.setLayout(constraints_layout)
        layout.addWidget(constraints_group)
        
        status_group = QGroupBox("Status")
        status_layout = QVBoxLayout()
        
        self.status_label = QLabel("Ready to solve..." if ANGR_AVAILABLE else "angr not available")
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        
        status_layout.addWidget(self.status_label)
        status_layout.addWidget(self.progress_bar)
        status_group.setLayout(status_layout)
        layout.addWidget(status_group)
        
        results_group = QGroupBox("Results")
        results_layout = QVBoxLayout()
        
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        self.results_text.setMaximumHeight(120)
        results_layout.addWidget(self.results_text)
        
        results_group.setLayout(results_layout)
        layout.addWidget(results_group)
        
        button_layout = QHBoxLayout()
        
        self.solve_btn = QPushButton("Solve with angr")
        self.solve_btn.clicked.connect(self.start_solving)
        self.solve_btn.setEnabled(ANGR_AVAILABLE)
        button_layout.addWidget(self.solve_btn)
        
        self.clear_btn = QPushButton("Clear Results")
        self.clear_btn.clicked.connect(self.clear_results)
        button_layout.addWidget(self.clear_btn)
        
        button_layout.addStretch()
        
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.close_dialog)
        button_layout.addWidget(close_btn)
        
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
        
    def on_input_method_changed(self, index):
        input_method = self.input_method_combo.currentData()
        self.stdin_type_combo.setVisible(input_method == "stdin")
    
    def start_solving(self):
        if not ANGR_AVAILABLE:
            show_message_box(
                "angr Not Available",
                "angr is not installed in Binary Ninja's Python environment.\n\n"
                "Please install it via: pip install angr",
                MessageBoxButtonSet.OKButtonSet,
                MessageBoxIcon.ErrorIcon
            )
            return
            
        target_str = self.target_input.text().strip()
        avoid_str = self.avoid_input.text().strip()
        input_size = self.size_input.value()
        input_method = self.input_method_combo.currentData()
        stdin_type = self.stdin_type_combo.currentData() if input_method == "stdin" else "symbolic_bytes"
        
        if not target_str:
            show_message_box(
                "Configuration Error",
                "Please enter a target string to find.",
                MessageBoxButtonSet.OKButtonSet,
                MessageBoxIcon.ErrorIcon
            )
            return
        
        constraint_options = {
            'zero_fill_memory': self.zero_memory_checkbox.isChecked(),
            'zero_fill_registers': self.zero_registers_checkbox.isChecked(),
            'uppercase': self.uppercase_checkbox.isChecked(),
            'lowercase': self.lowercase_checkbox.isChecked(),
            'digits': self.digits_checkbox.isChecked(),
            'printable': self.printable_checkbox.isChecked(),
            'allow_null': self.null_checkbox.isChecked(),
            'allow_newline': self.newline_checkbox.isChecked(),
        }
        
        char_constraints = [constraint_options['uppercase'], constraint_options['lowercase'],
                        constraint_options['digits'], constraint_options['printable'],
                        constraint_options['allow_null'], constraint_options['allow_newline']]
        
        if not any(char_constraints):
            show_message_box(
                "Configuration Error",
                "Please select at least one character constraint option.",
                MessageBoxButtonSet.OKButtonSet,
                MessageBoxIcon.ErrorIcon
            )
            return
        
        self.solve_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)
        self.status_label.setText("Starting symbolic execution...")
        
        self.solver_task = AngrSolverTask(
            self.bv, 
            target_str, 
            avoid_str, 
            input_size, 
            input_method, 
            constraint_options,
            stdin_type
        )
        
        self.progress_timer = QTimer()
        self.progress_timer.timeout.connect(self.check_progress)
        self.progress_timer.start(500)
        
        self.solver_task.start()
    
    def check_progress(self):
        if self.solver_task:
            if hasattr(self.solver_task, 'get_progress'):
                progress_text = self.solver_task.get_progress()
                self.status_label.setText(progress_text)
            
            if hasattr(self.solver_task, 'is_finished') and self.solver_task.is_finished():
                self.progress_timer.stop()
                self.solving_finished()
    
    def solving_finished(self):
        self.solve_btn.setEnabled(True)
        self.progress_bar.setVisible(False)
        
        if self.solver_task:
            if self.solver_task.error:
                self.status_label.setText(f"Error: {self.solver_task.error}")
                self.results_text.setText(f"Error during symbolic execution:\n{self.solver_task.error}")
                show_message_box(
                    "Solver Error",
                    f"An error occurred during symbolic execution:\n{self.solver_task.error}",
                    MessageBoxButtonSet.OKButtonSet,
                    MessageBoxIcon.ErrorIcon
                )
            elif self.solver_task.result:
                self.status_label.setText("Solution found!")
                input_method = self.input_method_combo.currentData()
                
                result_text = f"Input Method: {input_method.upper()}\n"
                result_text += f"Solution: {self.solver_task.result}\n\n"
                result_text += f"Hex: {self.solver_task.result.encode().hex()}\n"
                result_text += f"Length: {len(self.solver_task.result)} characters"
                self.results_text.setText(result_text)
            else:
                self.status_label.setText("No solution found")
                self.results_text.setText("No solution found with the given constraints.")
    
    def clear_results(self):
        self.results_text.clear()
        self.status_label.setText("Ready to solve...")
    
    def close_dialog(self):
        global _angr_dialog
        if self.progress_timer and self.progress_timer.isActive():
            self.progress_timer.stop()
        _angr_dialog = None
        self.close()

def show_angr_solver_dialog(bv):
    global _angr_dialog
    
    if _angr_dialog is not None:
        _angr_dialog.close()
        _angr_dialog = None
    
    _angr_dialog = AngrSolverDialog(bv)
    _angr_dialog.show()
    _angr_dialog.raise_()
    _angr_dialog.activateWindow()

if ANGR_AVAILABLE:
    PluginCommand.register(
        "nyxFault-AngryNinja", 
        "Use angr symbolic execution to find inputs that reach target states",
        show_angr_solver_dialog
    )
else:
    def show_angr_error(bv):
        show_message_box(
            "angr Not Available",
            "angr is not installed in Binary Ninja's Python environment.\n\n"
            "Please install it via: pip install angr",
            MessageBoxButtonSet.OKButtonSet,
            MessageBoxIcon.ErrorIcon
        )
    
    PluginCommand.register(
        "nyxFault-AngryNinja", 
        "Use angr symbolic execution to find inputs that reach target states (angr not installed)",
        show_angr_error
    )