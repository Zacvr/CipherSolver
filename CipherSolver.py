# Created By: Zacvr
# Created On: 4/15/20
# This program will help either a user encode a input or try and decode a input
# This was created to be an offline version of some websites as well as a quicker version of those sites
# It uses tkinter as a GUI to allow easy use by anyone

# Imports tkinter
from tkinter import *
from tkinter import ttk
import sys
from collections import defaultdict
import base64
import codecs

# Creates the tkinter root window, changes the name of the window and sets the window size
root = Tk()
root.title("Cipher Solver")

# This is commented out since it is not needed but might be used for
root.geometry("800x200")

# Creates the input frame on the root window at the top above the other frames
Input_Frame = Frame(root)
Input_Frame.pack(side="top")

# This is the first variable from the user input that we will convert
Input_Text = StringVar()


# This will be the variables for the encryption and decryption
binary_encoding = ""
decimal_encoding = ""
hex_encoding = ""

# Creates the decoding variables
binary_decoding = ""
decimal_decoding = ""
hex_decoding = ""
base64_decoding =""




# This creates the function we use to encode our Input text
def retrieve_input_encode():
    # Creates global variables to allow destroying previous variables without causing errors
    global Input_Encoding, Binary_Output_Encoding, Binary_Check, Decimal_Output_Encoding, Hex_Output_Encoding

    #Prints a welcome message and a shamless Github plug
    print  ("**************************************************")
    print  ("**   Thank you for using my program to encode   **"
          "\n** If you enjoyed this take a look at my Github!**"
          "\n**            https://zacvr.github.io/          **")
    print  ("**************************************************")

    # Destroys the previous Output (fixes minor issues with long output and then short outputs
    Input_Encoding.destroy(), Binary_Output_Encoding.destroy(), Decimal_Output_Encoding.destroy(), Hex_Output_Encoding.destroy()
    # Converts the user input into a more reliable variable
    Final_Input_Encoding = Input_Entry.get()
    # Creates a Label for the Input put in by the user
    # Creates a Label for the Input put in by the user
    Input_Encoding = Label(Encoding_Output_Frame, width=50, text="Input: " + str(Final_Input_Encoding))
    # Prints the user Input into the Terminal for easy copying
    print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
    print("Input:", Final_Input_Encoding)
    print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
    # Algorithm to convert the Input text to Binary
    binary_encoding = " ".join([format(ord(x), '#010b')[2:] for x in Final_Input_Encoding])
    # Creates a Label for the Binary that is converted from what the user input
    Binary_Output_Encoding = Label(Encoding_Output_Frame, text="Binary: " + binary_encoding)
    # Places the Binary output into the frame
    Binary_Output_Encoding.grid(column=1, row=6, sticky="W")
    # Prints the Binary into the Terminal for easy copying
    print("Binary: ", binary_encoding)


    decimal_encoding = " ".join(str(ord(x)) for x in Final_Input_Encoding)
    # Places a line inside of the Output Frame that will show our Decimal text
    Decimal_Output_Encoding = Label(Encoding_Output_Frame, text="Decimal: " + decimal_encoding)
    # Places the Decimal output into the frame
    Decimal_Output_Encoding.grid(column=1, row=7, sticky="W")
    # Prints the Decimal into the Terminal for easy copying
    print("Decimal: ", decimal_encoding)


    # This will convert the Hex to ASCII
    hex_encoding = " ".join(hex(ord(x))[2:] for x in Final_Input_Encoding)
    # Places a line inside of the Output Frame that will show our Hex text
    Hex_Output_Encoding = Label(Encoding_Output_Frame, text="ASCII to Hex: " + hex_encoding)
    # Places the Hex output into the frame
    Hex_Output_Encoding.grid(column=1, row=8, sticky="W")
    # Prints the Hex into the Terminal for easy copying
    print("ASCII to Hex: ", hex_encoding)


    # Creates a line to seperate each iteration we do
    print("____________________________________________________________________")


# This creates the function we use to decode our Input text
def retrieve_input_decode():
    # These are needed for the destroy command as well as to not cause issues
    global Input_Decoding, Binary_Output_Decoding, Base64_Output_Decoding, Decimal_Output_Decoding, Hex_Output_Decoding

    #Prints a welcome message and a shamless Github plug
    print("**************************************************")
    print("**   Thank you for using my program to decode   **"
        "\n** If you enjoyed this take a look at my Github!**"
        "\n**            https://zacvr.github.io/          **")
    print("**************************************************")


    # Destroys the previous Output (fixes minor issues with long output and then short outputs
    Input_Decoding.destroy(), Binary_Output_Decoding.destroy(), Decimal_Output_Decoding.destroy(), Hex_Output_Decoding.destroy()
    # Converts the user input into a more reliable variable
    Final_Input_Decoding = Input_Entry.get()
    # Creates a Label for the Input put in by the user
    Input_Decoding = Label(Decoding_Output_Frame, width=50, text="Input: " + str(Final_Input_Decoding))


    base64_decoding = Input_Entry.get()
    b = base64_decoding.encode("UTF-8")
    base64_decoding = base64.b64encode(b)
    base64_decoding = base64_decoding.decode("UTF-8")
    # Prints a message saying the user input was not in Decimal format
    Base64_Output_Decoding = Label(Decoding_Output_Frame, text="Base64: " + base64_decoding)
    # Places the Decimal output into the frame
    Base64_Output_Decoding.grid(column=1, row=5, sticky="W")


    # This was needed since Binary would output text while the others did not if input was nothing
    # Checks if the user Input was nothing
    if Final_Input_Decoding == "":
        # Shows the text all other data formats show when blank
        Binary_Output_Decoding = Label(Decoding_Output_Frame, text="Binary: ")
        # Places the Binary output into the frame
        Binary_Output_Decoding.grid(column=1, row=6, sticky="W")
    # If the user Input was not empty it goes to the other portion of the Binary script
    else:
            # This will do whats under try unless the except error is happening
            # This allows us to evade some common errors that can cause issues in tkinter as well as normal python
            try:
                # This will convert the user input (Binary) to ASCII
                binary_decoding = "".join([chr(int(b, 2)) for b in Final_Input_Decoding.split(" ")])
                # Creates a Label for the ASCII from the user input if it's in Binary
                Binary_Output_Decoding = Label(Decoding_Output_Frame, text="Binary: " + binary_decoding)
                # Places the Binary output into the frame
                Binary_Output_Decoding.grid(column=1, row=6, sticky="W")
            # This can post a message or do another portion of code instead of the error message popping up in terminal
            # If a ValueError is raised it shall execute this portion
            except ValueError:
                # Prints that the user input was not in Binary format
                Binary_Output_Decoding = Label(Decoding_Output_Frame, text="Binary: This does not seem to be a Binary based encoding(ValueError) ")
                # Places the Binary message into the output frame
                Binary_Output_Decoding.grid(column=1, row=6, sticky="W")
            # If a OverflowError is raised it shall execute this portion
            except OverflowError:
                # Prints that the user input was not in Binary format
                Binary_Output_Decoding = Label(Decoding_Output_Frame, text="Binary: This does not seem to be a Binary based encoding(OverFlowError) ")
                # Places the Binary message into the output frame
                Binary_Output_Decoding.grid(column=1, row=6, sticky="W")
    # As before this will do the top portion unless a except happens, in this case a ValueError
    try:
            # This converts Decimal into ASCII
            decimal_decoding = "".join(chr(int(c)) for c in Final_Input_Decoding.split())
            # Places a line inside of the Output Frame that will show our Decimal text
            Decimal_Output_Decoding = Label(Decoding_Output_Frame, text="Decimal: " + decimal_decoding)
            # Places the Decimal output into the frame
            Decimal_Output_Decoding.grid(column=1, row=7, sticky="W")
    # If a ValueError is raised it will do the next portion
    except ValueError:
        # Prints a message saying the user input was not in Decimal format
        Decimal_Output_Decoding = Label(Decoding_Output_Frame,text="Decimal: This does not seem to be a Decimal based encoding(ValueError) ")
        # Places the Decimal output into the frame
        Decimal_Output_Decoding.grid(column=1, row=7, sticky="W")
    # If a OverflowError is raised it shall execute this portion
    except OverflowError:
        # Prints a message saying the user input was not in Decimal format
        Decimal_Output_Decoding = Label(Decoding_Output_Frame,text="Decimal: This does not seem to be a Decimal based encoding (OverflowError) ")
        # Places the Decimal output into the frame
        Decimal_Output_Decoding.grid(column=1, row=7, sticky="W")

    # As before this will do the top portion unless a except happens, in this case a ValueError
    try:
            # This converts Hex to ASCII ( changed
            hex_decoding = bytes.fromhex(Final_Input_Decoding).decode('latin-1')
            # Places a line inside of the Output Frame that will show our Hex text
            Hex_Output_Decoding = Label(Decoding_Output_Frame, text="Hex to ASCII: " + hex_decoding)
            # Places the Hex output into the frame
            Hex_Output_Decoding.grid(column=1, row=8, sticky="W")

            # This converts Hex to ASCII
            # This was added in as a second step allowing special characters to be checked first
            hex_decoding = bytes.fromhex(Final_Input_Decoding).decode('utf-8')
            # Places a line inside of the Output Frame that will show our Hex text
            Hex_Output_Decoding = Label(Decoding_Output_Frame, text="Hex to ASCII: " + hex_decoding)
            # Places the Hex output into the frame
            Hex_Output_Decoding.grid(column=1, row=8, sticky="W")

        # If a ValueError is raised it will do the next portion
    except ValueError:
        # If a value error is found it will post this message
        Hex_Output_Decoding = Label(Decoding_Output_Frame, text="Hex to ASCII :This does not seem to be a Hex based encoding(Value Error) ")
        # Places the Hex output into the frame
        Hex_Output_Decoding.grid(column=1, row=8, sticky="W")






    # Prints the user input into the terminal
    print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
    print("Input: \t\t\t"+ Final_Input_Decoding)
    print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
    print("Base64: \t\t" + base64_decoding)



    # If the user input was empty it will post the message
    if Final_Input_Decoding == "":
        # Posts what the other formats would look like
        print("Binary: \t")
    # If the user input was not empty it will go here for Binary
    else:
        # It will try to print the binary as ASCII
        try:
            # Prints said ASCII
            print("Binary: \t", binary_decoding)
        # If a UnboundLocalError is raised it shall execute this portion
        except UnboundLocalError:
            # Prints letting the user know an error occured
            print("Binary: \t\tIt seems like Binary caused an error(UnboundLocalError) ")


    try:
        # Prints the ASCII from Decimal into the Terminal for easy copying
        print("Decimal: \t\t"+ decimal_decoding)
    # If a UnboundLocalError is raised it shall execute this portion
    except UnboundLocalError:
        # If a UnboundLocalError happens prints this message to terminal
        print("Decimal: \t\tIt seems like Decimal caused an error(UnboundLocalError) ")


    try:
        # Prints the ASCII from Hex into the Terminal for easy copying
        print("Hex:\t\t\t"+ hex_decoding)
    # If a UnboundLocalError is raised it shall execute this portion
    except UnboundLocalError:
        # If a UnboundLocalError happens prints this message to terminal
        print("Hex to ASCII: \tIt seems like Hex to ASCII caused an error(UnboundLocalError) ")






# Creates a line to seperate each iteration we do
print("____________________________________________________________________")



# Creates a random variable for our text next to our Entry input
Input_Help_Text = StringVar()
# Changes the text for the Entry input
Input_Help_Text.set("Input your text here:")
# This puts the Input Help Text in a label
InputDir = Label(Input_Frame, textvariable=Input_Help_Text)
# This adds that label to the side of the Entry input box
InputDir.grid(column=0, row=0)
# Adds an Entry box to input text
Input_Entry = Entry(Input_Frame)
# Adds that Entry box onto the Input Frame
Input_Entry.grid(column=5, row=0)





# Used to have tabs inside of the Python script via ttk Module
tab_control = ttk.Notebook(root)


# Naming/Creating Encoding tab
Encoding = ttk.Frame(tab_control)
# Adding Encoding tab to GUI
tab_control.add(Encoding, text='Encoding')

# Names the output frame and shows it will be under the Decoding tab
Encoding_Output_Frame = LabelFrame(Encoding, text="Encoding Results")
# Places the Encoding Output Frame into the Encoding parent frame
Encoding_Output_Frame.grid(column=0, row=5)


# Creates a variable to hold our User Input
Final_Input_Encoding = Input_Entry.get()
# Creates a Label for user Input
Input_Encoding = Label(Encoding_Output_Frame, width=50, text="Input: " + str(Final_Input_Encoding))

# Places a line inside of the Output Frame that will show our Binary text
Binary_Output_Encoding = Label(Encoding_Output_Frame, text="Binary: " + binary_encoding)
# Places the Binary output into the frame
Binary_Output_Encoding.grid(column=1, row=6, sticky="W")

# Places a line inside of the Output Frame that will show our Decimal text
Decimal_Output_Encoding = Label(Encoding_Output_Frame, text="Decimal: " + decimal_decoding)
# Places the Decimal output into the frame
Decimal_Output_Encoding.grid(column=1, row=7, sticky="W")

Hex_Output_Encoding = Label(Encoding_Output_Frame, text="ASCII to Hex: ")
# Places the Hex output into the frame
Hex_Output_Encoding.grid(column=1, row=8, sticky="W")





# Starts the retrieve input encode Function
encoding_encode = Button(Encoding, text="Encode", command=retrieve_input_encode)
# Adds the encoding function button to Encoding tab
encoding_encode.grid(column=0, row=3, sticky="W")






# Creates/Names Decoding tab via ttk Module
Decoding = ttk.Frame(tab_control)
# Puts text on the Decoding tab
tab_control.add(Decoding, text='Decoding')

# Names the output frame and shows it will be under the Decoding tab
Decoding_Output_Frame = LabelFrame(Decoding, text="Decoding Results")
# Places the Encoding Output Frame into the Encoding parent frame
Decoding_Output_Frame.grid(column=0, row=5)

# Creates a variable to hold our User Input
Final_Input_Decoding = Input_Entry.get()
# Creates a Label for user Input
Input_Decoding = Label(Decoding_Output_Frame, width=50, text="Input: " + str(Final_Input_Decoding))

# Places a line inside of the Output Frame that will show our Binary text
Binary_Output_Decoding = Label(Decoding_Output_Frame, text="Binary: " + binary_encoding)
# Places the Binary output into the frame
Binary_Output_Decoding.grid(column=1, row=6, sticky="W")

# Places a line inside of the Output Frame that will show our Decimal text
Decimal_Output_Decoding = Label(Decoding_Output_Frame, text="Decimal: " + decimal_decoding)
# Places the Decimal output into the frame
Decimal_Output_Decoding.grid(column=1, row=7, sticky="W")

# Places a line inside of the Output Frame that will show our Hex to ASCII text
Hex_Output_Decoding = Label(Decoding_Output_Frame, text="Hex to ASCII: ")
# Places the Hex output into the frame
Hex_Output_Decoding.grid(column=1, row=8, sticky="W")



Base64_Output_Decoding = Label(Decoding_Output_Frame, text="Base64: ")

Base64_Output_Decoding.grid(column=1, row=5, sticky="W")






# Starts the retrieve input decode Function
decoding_decode = Button(Decoding, text="Decode", command=retrieve_input_decode, wraplength=400)
# Adds the decoding function button to Decoding tab
decoding_decode.grid(column=0, row=3, sticky="W")



# Atbash

def atbash():
    atbash_cipher = {'A': 'Z', 'a': 'z', 'B': 'Y', 'b': 'y', 'C': 'X', 'c': 'x', 'D': 'W', 'd': 'w', 'E': 'V', 'e': 'v',
                 'F': 'U', 'f': 'u', 'G': 'T', 'g': 't', 'H': 'S', 'h': 's', 'I': 'R', 'i': 'r', 'J': 'Q', 'j': 'q',
                 'K': 'P', 'k': 'p', 'L': 'O', 'l': 'o', 'M': 'N', 'm': 'n', 'N': 'M', 'n': 'm', 'O': 'L', 'o': 'l',
                 'P': 'K', 'p': 'k', 'Q': 'J', 'q': 'j', 'R': 'I', 'r': 'i', 'S': 'H', 's': 'h', 'T': 'G', 't': 'g',
                 'U': 'F', 'u': 'f', 'V': 'E', 'v': 'e', 'W': 'D', 'w': 'd', 'X': 'C', 'x': 'c', 'Y': 'B', 'y': 'b',
                 'Z': 'A', 'z': 'a', ' ': ' ', '.': '.', ',': ',', '?': '?', '!': '!', '\'': '\'', '\"': '\"',
                 ':': ':', ';': ';', '\(': '\)', '\)': '\)', '\[': '\[', '\]': '\]', '\-': '\-', '1': '1',
                 '2': '2', '3': '3', '4': '4', '5': '5', '6': '6', '7': '7', '8': '8', '9': '9', '0': '0'}

    message = Input_Entry.get()
    print("Atbash: \t", end="")
    for char in message:
        if char in atbash_cipher.keys():
            print(atbash_cipher[char], end="")
    print("")




# Caesar Ciphers

def Caesar (s, offset):
    chars = 'abcdefghijklmnopqrstuvwxyz'
    return s.translate (str.maketrans (chars, chars [offset:] + chars [:offset] ) )

def Caesar_Cipher ():
    global Caesar_Output_Decoding
    #Caesar_Output_Decoding.destroy()
    s = Input_Entry.get().lower()
    print("********************************************************************")
    print("Brute Forcing Caesar Cipher")
    for offset in range (26):
        #Caesar_Output_Decoding = Message(Decoding_Caesar_Frame, text="Offset {}: {}".format(offset, Caesar(s, (-offset) % 26)))
        #Caesar_Output_Decoding.grid(column=1, row=6, sticky="W")
        print("Offset {}:\t{}".format(offset, Caesar(s, (-offset) % 26)))
    print("********************************************************************")



def Rot_13():
    print("Rot 13: \t"+codecs.decode(Input_Entry.get(), "rot13"))









# Creates Decodes Cipher Tab

# Creates/Names Decoding tab via ttk Module
Decoding_Ciphers = ttk.Frame(tab_control)
# Puts text on the Decoding tab
tab_control.add(Decoding_Ciphers, text='Decode Ciphers')

# Names the output frame and shows it will be under the Decoding Ciphers tab
Decoding_Ciphers_Frame = LabelFrame(Decoding_Ciphers, text="Decoding Results")
# Places the Encoding Output Frame into the Encoding parent frame
Decoding_Ciphers_Frame.grid(column=0, row=1, columnspan=2)

# Creates a variable to hold our User Input
Final_Input_Decoding = Input_Entry.get()
# Creates a Label for user Input
Input_Decoding = Label(Decoding_Ciphers_Frame, width=50, text="Input: " + str(Final_Input_Decoding))





# Starts the retrieve input decode Function
decoding_decode = Button(Decoding_Ciphers, text="Atbash", command=atbash, wraplength=400)
# Adds the decoding function button to Decoding tab
decoding_decode.grid(column=0, row=0, sticky="W")

Atbash_Output_Decoding = Label(Decoding_Ciphers_Frame)
# Places the Binary output into the frame
Atbash_Output_Decoding.grid(column=1, row=6, sticky="W")




# Places a line inside of the Output Frame that will show our Binary text
Caesar_Output_Decoding = Label(Decoding_Ciphers_Frame, text="This will be printed inside of the terminal")
# Places the Binary output into the frame
Caesar_Output_Decoding.grid(column=1, row=6, sticky="W")



# Starts the retrieve input decode Function
decoding_decode = Button(Decoding_Ciphers, text="Brute Force Caesar", command=Caesar_Cipher, wraplength=400)
# Adds the decoding function button to Decoding tab
decoding_decode.grid(column=1, row=0, sticky="W")


# Starts the retrieve input decode Function
decoding_decode = Button(Decoding_Ciphers, text="Rot 13", command=Rot_13, wraplength=400)
# Adds the decoding function button to Decoding tab
decoding_decode.grid(column=2, row=0, sticky="W")


# Used for the tab control ( the Encoding and Decoding Tabs(not fully sure what it does but it is needed)
tab_control.pack(expand=1, fill='both')

# Runs the tkinter loop
root.mainloop()
