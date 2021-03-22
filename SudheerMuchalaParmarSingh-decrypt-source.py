# CRYPTANALYSIS OF A CLASS OF CIPHERS BASED ON FREQUENCY ANALYSIS AND INDEX OF COINCIDENCE
#
#   Authors: Shashank Sudheer, Abhigna Muchala, Saurabh Parmar, Jaspreet Singh
#
#   Description: Solves a class of ciphers based on given candidate plaintexts.


import copy

MAX_KEY_LENGTH_GUESS = 24
ALPHABET = 'abcdefghijklmnopqrstuvwxyz '
CHARACTERS = [' ', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z']
keySpace = [x for x in range(27)]

# Array containing the relative frequency of each letter in the English language
english_frequences = [0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015,
					  0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749,
					  0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758,
					  0.00978, 0.02360, 0.00150, 0.01974, 0.00074]

def countLetters(msg):
    count = {' ': 0, 'a': 0, 'b': 0, 'c': 0, 'd': 0, 'e': 0, 'f': 0,
           'g': 0, 'h': 0, 'i': 0, 'j': 0, 'k': 0, 'l': 0, 'm': 0, 'n': 0,
           'o': 0, 'p': 0, 'q': 0, 'r': 0, 's': 0, 't': 0, 'u': 0, 'v': 0,
           'w': 0, 'x': 0, 'y': 0, 'z': 0}

    msg = msg.lower()

    freqLst = []

    for i in range(len(msg)):
        if msg[i] in ALPHABET:
            count[msg[i]] += 1

    for key in count:
        freqLst.append(count[key] * 1.0/float(len(msg)))

    return freqLst

# Array containing relative frequencies of items from all candidate plaintexts
plaintext_frequencies = countLetters("undercurrents laryngeal elevate betokened chronologist ghostwrites ombres dollying airship probates music debouching countermanded rivalling linky wheedled heydey sours nitrates bewares rideable woven rerecorded currie vasectomize mousings rootstocks langley propaganda numismatics foetor subduers babcock jauntily ascots nested notifying mountainside dirk chancellors disassociating eleganter radiant convexity appositeness axonic trainful nestlers applicably correctional stovers organdy bdrm insis leonardo oxygenate cascade fashion fortifiers annelids co intimates cads expanse rusting quashing julienne hydrothermal defunctive permeation sabines hurries precalculates discourteously fooling pestles pellucid circlers hampshirites punchiest extremist cottonwood dadoes identifiers retail gyrations dusked opportunities ictus misjudge neighborly aulder larges predestinate bandstand angling billet drawbridge pantomimes propelled leaned gerontologists candying ingestive museum chlorites maryland s hermitage rejoices oxgall bloodstone fisticuff huguenot janitress assailed eggcup jerseyites fetas leipzig copiers pushiness fesse precociously modules navigates gaiters caldrons lisp humbly datum recite haphazardly dispassion calculability circularization intangibles impressionist jaggy ascribable overseen copses devolvement permutationists potations linesmen hematic fowler pridefully inversive malthus remainders multiplex petty hymnaries cubby donne ohioans avenues reverts glide photos antiaci biorhythmic personalizing abjure greets rewashed thruput kashmir chores fiendishly combatting alliums lolly milder postpaid larry annuli codgers apostatizing scrim carillon rust grimly lignifying lycanthrope samisen founds millimeters pentagon humidification checkup hilts agonise crumbs rejected kangaroo forenoons grazable acidy duellist potent recyclability capture memorized psalmed meters decline deduced after oversolicitousness demoralizers ologist conscript cronyisms melodized girdles nonago cabooses meltdowns bigmouth makework flippest neutralizers gipped mule antithetical imperials carom masochism stair retsina dullness adeste corsage saraband promenaders gestational mansuetude fig redress pregame borshts pardoner reforges refutations calendal moaning doggerel dendrology governs ribonucleic circumscriptions reassimilating machinize rebuilding mezcal fluoresced antepenults blacksmith constance furores chroniclers overlie hoers jabbing resigner quartics polishers mallow hovelling ch")

CAND_1 = "cabooses meltdowns bigmouth makework flippest neutralizers gipped mule antithetical imperials carom masochism stair retsina dullness adeste corsage saraband promenaders gestational mansuetude fig redress pregame borshts pardoner reforges refutations calendal moaning doggerel dendrology governs ribonucleic circumscriptions reassimilating machinize rebuilding mezcal fluoresced antepenults blacksmith constance furores chroniclers overlie hoers jabbing resigner quartics polishers mallow hovelling ch"
CAND_2 = "biorhythmic personalizing abjure greets rewashed thruput kashmir chores fiendishly combatting alliums lolly milder postpaid larry annuli codgers apostatizing scrim carillon rust grimly lignifying lycanthrope samisen founds millimeters pentagon humidification checkup hilts agonise crumbs rejected kangaroo forenoons grazable acidy duellist potent recyclability capture memorized psalmed meters decline deduced after oversolicitousness demoralizers ologist conscript cronyisms melodized girdles nonago"
CAND_3 = "hermitage rejoices oxgall bloodstone fisticuff huguenot janitress assailed eggcup jerseyites fetas leipzig copiers pushiness fesse precociously modules navigates gaiters caldrons lisp humbly datum recite haphazardly dispassion calculability circularization intangibles impressionist jaggy ascribable overseen copses devolvement permutationists potations linesmen hematic fowler pridefully inversive malthus remainders multiplex petty hymnaries cubby donne ohioans avenues reverts glide photos antiaci"
CAND_4 = "leonardo oxygenate cascade fashion fortifiers annelids co intimates cads expanse rusting quashing julienne hydrothermal defunctive permeation sabines hurries precalculates discourteously fooling pestles pellucid circlers hampshirites punchiest extremist cottonwood dadoes identifiers retail gyrations dusked opportunities ictus misjudge neighborly aulder larges predestinate bandstand angling billet drawbridge pantomimes propelled leaned gerontologists candying ingestive museum chlorites maryland s"
CAND_5 = "undercurrents laryngeal elevate betokened chronologist ghostwrites ombres dollying airship probates music debouching countermanded rivalling linky wheedled heydey sours nitrates bewares rideable woven rerecorded currie vasectomize mousings rootstocks langley propaganda numismatics foetor subduers babcock jauntily ascots nested notifying mountainside dirk chancellors disassociating eleganter radiant convexity appositeness axonic trainful nestlers applicably correctional stovers organdy bdrm insis"
CAND_6 = "awesomeness hearkened aloneness beheld courtship swoops memphis attentional pintsized rustics hermeneutics dismissive delimiting proposes between postilion repress racecourse matures directions pressed miserabilia indelicacy faultlessly chuted shorelines irony intuitiveness cadgy ferries catcher wobbly protruded combusting unconvertible successors footfalls bursary myrtle photocompose"

# Returns the Index of Councidence for the "section" of ciphertext given
def get_index_c(ciphertext):
	
	N = float(len(ciphertext))
	frequency_sum = 0.0

	# Using Index of Coincidence formula
	for letter in CHARACTERS:
	    frequency_sum+= ciphertext.count(letter) * (ciphertext.count(letter)-1)
    
	# Using Index of Coincidence formula
	ic = frequency_sum/(N*(N-1))
	return ic

# Returns the key length with the highest average Index of Coincidence
def get_key_length(ciphertext):
    ic_table=[]

    # Splits the ciphertext into sequences based on the guessed key length from 0 until the max key length guess (20)
    # Ex. guessing a key length of 2 splits the "12345678" into "1357" and "2468"
    # This procedure of breaking ciphertext into sequences and sorting it by the Index of Coincidence
    # The guessed key length with the highest IC is the most porbable key length
    for guess_len in range(MAX_KEY_LENGTH_GUESS):
        ic_sum=0.0
        avg_ic=0.0
        for i in range(guess_len):
            sequence=""
            # breaks the ciphertext into sequences
            for j in range(0, len(ciphertext[i:]), guess_len):
                sequence += ciphertext[i+j]
            ic_sum+=get_index_c(sequence)
        # obviously don't want to divide by zero
        if not guess_len==0:
            avg_ic=ic_sum/guess_len
        ic_table.append(avg_ic)

    # returns the index of the highest Index of Coincidence (most probable key length)
    best_guess = ic_table.index(sorted(ic_table, reverse = True)[0])
    second_best_guess = ic_table.index(sorted(ic_table, reverse = True)[1])

    # Since this program can sometimes think that a key is literally twice itself, or three times itself, 
    # it's best to return the smaller amount.
    # Ex. the actual key is "dog", but the program thinks the key is "dogdog" or "dogdogdog"
    # (The reason for this error is that the frequency distribution for the key "dog" vs "dogdog" would be nearly identical)
    if best_guess % second_best_guess == 0:
        return second_best_guess
    else:
        return best_guess

def freq_analysis(sequence):
    all_chi_squareds = [0] * 27

    for i in range(len(CHARACTERS)):

        chi_squared_sum = 0.0

        sequence_offset = [CHARACTERS[(CHARACTERS.index(sequence[j])-i) % 27] for j in range(len(sequence))]
        v = [0] * 27
        # count the numbers of each letter in the sequence_offset
        for l in sequence_offset:
            v[CHARACTERS.index(l)] += 1
        # divide the array by the length of the sequence to get the frequency percentages
        for j in range(27):
            v[j] *= (1.0/float(len(sequence)))

        # now you can compare to the plaintext frequencies
        for j in range(27):
            chi_squared_sum+=((v[j] - float(plaintext_frequencies[j]))**2)/float(plaintext_frequencies[j])

        # add it to the big table of chi squareds
        all_chi_squareds[i] = chi_squared_sum

    # return the number of the key that it needs to be shifted by
    # this is found by the smallest chi-squared statistic (smallest different between sequence distribution and 
    # english distribution)
    shift = all_chi_squareds.index(min(all_chi_squareds))

    # return the number
    return shift

def get_key(ciphertext, key_length):
	key = []

	# Calculate letter frequency table for each letter of the key
	for i in range(key_length):
		sequence=""
		# breaks the ciphertext into sequences
		for j in range(0,len(ciphertext[i:]), key_length):
			sequence+=ciphertext[i+j]
		key.append(freq_analysis(sequence))

	return key

# Returns the plaintext given the ciphertext and a key
def decrypt(ciphertext, key):
    plaintext = []
    # decrypt using standard vignere cipher
    for i in range(len(ciphertext)):
        j = i % len(key)
        shift = key[j]
        plaintextInd = (CHARACTERS.index(ciphertext[i]) - shift) % 27
        plaintext.append(CHARACTERS[plaintextInd])
        i += 1
    return ''.join(plaintext)

# Function encrypts based on a polyalphabetic cipher (Vignere)
def encrypt(message, key, cipher):
    message = message.lower()
    ciphertext = []

    # encrypt using standard vignere cipher
    if cipher == "v":
        for i in range(len(message)):
            j = i % len(key)
            shift = key[j]
            cipherInd = (CHARACTERS.index(message[i]) + shift) % 27
            ciphertext.append(CHARACTERS[cipherInd])
            i += 1
        return ''.join(ciphertext)

def solvedKeyTest(ciphertext, key):
    plaintextArray = [CAND_1, CAND_2, CAND_3, CAND_4, CAND_5]
    tempKey = copy.deepcopy(key)
    for plaintext in plaintextArray:
        i = 0
        j = 0
        # count variable stores if all key elements have been tested
        # allows for each element of key to be looped through until all possible elements
        # have been tested
        count = len(tempKey)
        while (count > 0):
            testSingleKey = []
            testSingleKey.append(tempKey[j])
            plainSym = decrypt(ciphertext[i], testSingleKey)
            if i == 5:
                return plaintext
            elif plainSym == plaintext[i]:
                i += 1
                count = len(tempKey)
            else:
                j += 1
                count -= 1
                j = j % len(tempKey)
            

    return "could not find plaintext"

def main():
    exec_num = 1
    SOLVED_KEY = []
    ask = True
    print("--------------------------STARTING TEST----------------------------")
    while ask:
        print("-------------------------- STARTING EXECUTION", exec_num, "----------------------------")
        text = input("Enter e to encrypt, or d to decrypt: ")
        if text =='e':
            plaintext = input("Enter plaintext to encrypt: ")

            key = [17, 19, 3, 4, 7, 17, 5]
                    # [4, 19, 3, 5, 10, 7, 17]
            ciphertext = encrypt(plaintext, key, "v")
            print("Ciphertext: {}".format(ciphertext))

            ask = False	
        elif text == 'd':
            if (len(SOLVED_KEY) == 0):
                ciphertext = input("Enter ciphertext to decrypt: ")

                key_length=get_key_length(ciphertext)

                key = get_key(ciphertext, key_length)
                SOLVED_KEY = key
                print("-------------- SOLVED KEY --------------------------")
                print(key)
                plaintext = decrypt(ciphertext, key)

                print("--------------SOLVED PLAINTEXT-----------------------")
                print(plaintext)
                print("--------------END EXECUTION-----------------------")
            else:
                ciphertext = input("Enter ciphertext to decrypt: ")
                plaintext = solvedKeyTest(ciphertext, SOLVED_KEY)

                print("--------------SOLVED PLAINTEXT-----------------------")
                print(plaintext)
                print("--------------END EXECUTION-----------------------")

        else:
            print("Not a valid input")
        
        exec_num += 1

if __name__ == '__main__':
	main()