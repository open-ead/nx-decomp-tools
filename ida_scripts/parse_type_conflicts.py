import difflib
import tkinter as tk
import tkinter.filedialog as tkfd
import Levenshtein
from pathlib import Path

file = tkfd.askopenfilename(title="Select type_conflicts-[...].txt")
if file.endswith("-manual.txt") or file.endswith("-keep_old.txt"):
    raise ValueError("Please select a type_conflicts-[...].txt file, not a manual or keep_old file.")
with open(file, "r") as f:
    content = f.read()
content = content.strip().split("Conflict for type", 1)[1].strip()

conflicts = {}
for conflict in content.split("Conflict for type"):
    typename = conflict.split("\n", 1)[0].strip().rstrip(":")
    parts = conflict.split("\n", 1)[1].split("Old: ", 1)[1].strip().split("\nNew: ", 1)
    olddef = parts[0].strip()
    newdef = parts[1].strip()
    conflicts[typename] = (olddef, newdef)
total_conflicts = len(conflicts)

current_conflict = None
keep_old = None
manual = None

def resolve_conflict(choice):
    global keep_old, manual
    if current_conflict is not None:
        olddef, newdef = conflicts[current_conflict]
        del conflicts[current_conflict]
        if choice == "new":
            # keep new definition
            pass
        elif choice == "old":
            keep_old = (current_conflict, olddef)
        elif choice == "manual":
            manual = (current_conflict, (olddef, newdef))
        save_progress()
    show_next()

def save_progress():
    global keep_old, manual
    with open(file, "w") as f:
        for name, (oldtype, newtype) in conflicts.items():
            f.write(f"Conflict for type {name}:\n")
            f.write(f"Old: {oldtype}\n")
            f.write(f"New: {newtype}\n")
            f.write("\n")
    if manual:
        with open(Path(file).parent / "type_conflicts-manual.txt", "a") as f:
            name, (oldtype, newtype) = manual
            f.write(f"Conflict for type {name}:\n")
            f.write(f"Old: {oldtype}\n")
            f.write(f"New: {newtype}\n")
            f.write("\n")
            manual = None
        print(f"Saved manual resolution to type_conflicts-manual.txt. Please resolve them manually, or move them to a different file and open it with this program again.")
    if keep_old:
        with open(Path(file).parent / "type_conflicts-keep_old.txt", "a") as f:
            name, oldtype = keep_old
            f.write(f"Conflict for type {name}:\n")
            f.write(f"Old: {oldtype}\n")
            f.write("\n")
            keep_old = None
        print(f"Saved old definition to type_conflicts-keep_old.txt. Insert them into `OdysseyDecomp` and re-import or manually insert type into IDA.")

def show_next():
    global current_conflict
    if not conflicts:
        progress.config(text="All conflicts resolved!")
        old_text.delete(1.0, tk.END)
        new_text.delete(1.0, tk.END)
        diff_text.delete(1.0, tk.END)
        return
    current_conflict = next(iter(conflicts))
    olddef, newdef = conflicts[current_conflict]
    
    old_text.config(state=tk.NORMAL)
    new_text.config(state=tk.NORMAL)
    diff_text.config(state=tk.NORMAL)
    old_text.delete(1.0, tk.END)
    new_text.delete(1.0, tk.END)
    diff_text.delete(1.0, tk.END)
    
    old_text.tag_configure("insert", background="lightgreen")
    old_text.tag_configure("delete", background="lightcoral")
    new_text.tag_configure("insert", background="lightgreen")
    new_text.tag_configure("delete", background="lightcoral")
    diff_text.tag_configure("insert", background="lightgreen")
    diff_text.tag_configure("delete", background="lightcoral")
    
    matcher = difflib.SequenceMatcher(None, olddef, newdef)
    for opcode, a0, a1, b0, b1 in Levenshtein.opcodes(olddef, newdef):
        if opcode == "equal":
            diff_text.insert(tk.END, olddef[a0:a1])
            old_text.insert(tk.END, olddef[a0:a1])
            new_text.insert(tk.END, newdef[b0:b1])
        elif opcode == "insert":
            diff_text.insert(tk.END, newdef[b0:b1], "insert")
            new_text.insert(tk.END, newdef[b0:b1], "insert")
        elif opcode == "delete":
            diff_text.insert(tk.END, olddef[a0:a1], "delete")
            old_text.insert(tk.END, olddef[a0:a1], "delete")
        elif opcode == "replace":
            diff_text.insert(tk.END, newdef[b0:b1], "insert")
            diff_text.insert(tk.END, olddef[a0:a1], "delete")
            old_text.insert(tk.END, olddef[a0:a1], "delete")
            new_text.insert(tk.END, newdef[b0:b1], "insert")

    old_text.config(state=tk.DISABLED)
    new_text.config(state=tk.DISABLED)
    diff_text.config(state=tk.DISABLED)

    progress.config(text=f"{total_conflicts-len(conflicts)}/{total_conflicts}")

root = tk.Tk()
root.title("Resolving Type Conflicts")

progress = tk.Label(root, text=f"0/{total_conflicts}")
progress.grid(row=0, column=0, columnspan=6, pady=10)

old_text = tk.Text(root, height=20, width=100)
old_text.grid(row=1, column=0, columnspan=3, sticky="news")
new_text = tk.Text(root, height=20, width=100)
new_text.grid(row=1, column=3, columnspan=3, sticky="news")

diff_text = tk.Text(root, height=20, width=210)
diff_text.grid(row=2, column=0, columnspan=6, sticky="news")

button_old = tk.Button(root, text="Keep Old", command=lambda: resolve_conflict("old"))
button_old.grid(row=3, column=0, columnspan=2)
button_manual = tk.Button(root, text="Manual Edit", command=lambda: resolve_conflict("manual"))
button_manual.grid(row=3, column=2, columnspan=2)
button_new = tk.Button(root, text="Keep New", command=lambda: resolve_conflict("new"))
button_new.grid(row=3, column=4, columnspan=2)

for i in range(6):
    root.grid_columnconfigure(i, weight=1)
root.grid_rowconfigure(0, weight=0)
root.grid_rowconfigure(1, weight=1)
root.grid_rowconfigure(2, weight=1)
root.grid_rowconfigure(3, weight=0)

show_next()
root.mainloop()
