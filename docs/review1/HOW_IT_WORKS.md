# How the system works, in plain terms

Read this once before the presentation. It explains the whole flow, and then
explains the model in detail, because that is the question you are most likely
to be asked.

---

## Part 1: What happens when someone runs a scan

Say a developer points our tool at their project. Five things happen.

### Step 1: Read the list

Every project has a file listing what it needs. In Python it is
`requirements.txt`. In JavaScript it is `package.json`. We read that file.

Say it lists 7 packages.

### Step 2: Work out the real list

Those 7 packages need other packages, and those need more. We ask npm and PyPI
"what does this one need", follow every branch, and build the full tree.

7 packages on paper often becomes 300 in reality. **This is why the problem
exists.** The developer chose 7. They got 300.

### Step 3: Look at each package (this is where the model works)

For each package we download it and read the code **without running it**.

We are looking for specific behaviours. Does it run code the moment you install
it? Does it read SSH keys or browser passwords? Does it send data somewhere? Is
the code deliberately scrambled to be unreadable? Is the name suspiciously close
to a popular package?

We turn all of that into **58 numbers**. That row of numbers goes into the model,
and the model gives back one score between 0 and 1. Above 0.6 we call it
malicious. Between 0.3 and 0.6 we call it suspicious. Below that it is fine.

### Step 4: Look up known bugs

Separately, we send the list of packages and versions to OSV.dev, which is
Google's public vulnerability database. It tells us which versions have publicly
known security bugs, each with a CVE number.

On a real project this comes back with 100 to 300 results. **No machine learning
here.** It is a database lookup.

### Step 5: Work out which of those bugs actually matter

This is the part that makes the project interesting.

We read the developer's own code and build a map of which function calls which
function. Then we start from where the program actually begins and search for a
path to the vulnerable function.

If we find a path, we report it and show the path. If the package is never even
imported, we say so. On our test project this took 92 reported bugs down to 3.

**Also no machine learning here.** It is a graph search, which is a standard
computer science algorithm.

---

## Part 2: What is "the model", exactly

**The model is the part that decides whether a package is malicious.**

It only does Step 3. Steps 4 and 5, the vulnerability half, do not use it at all.

If someone asks "where is the AI in your project", the answer is: the model in
Step 3. The reachability half is a deterministic algorithm.

### The doctor analogy

Think about a junior doctor and an experienced doctor.

The **junior doctor** follows a printed checklist. Fever adds 2 points, cough
adds 1 point, over 8 points means send to hospital. Simple, predictable, and it
gets a lot of cases wrong because real patients do not fit a fixed checklist.

That is our **rules engine**. We built one, and it scores 0.57.

The **experienced doctor** has seen 2,000 patients. Nobody gave them a points
table. They learned from experience that a cough alone means little, but a cough
with a fever and a particular chest sound is serious. They weigh the same
symptoms far better because they have seen how they combine.

That is our **model**. It scores 0.95 on the same data.

Both doctors look at the same symptoms. The difference is that one was told the
weights and the other worked them out from experience.

### What kind of model is it

It is called a **gradient boosted decision tree**. You do not need to defend the
name, but here is what it means.

A **decision tree** is a flowchart of yes or no questions. "Does it run code at
install time? If yes, does it also read credential files? If yes, does it also
send data out?"

One tree on its own is weak. So we build **hundreds of small trees**, where each
new tree focuses on the cases the previous ones got wrong. The final score is all
of them voting together. That is the "boosted" part.

**We chose this on purpose, for three reasons:**

1. We have about 1,800 examples. Deep learning needs millions. With small data,
   trees work better.
2. Trees can tell you which inputs mattered most. That matters because we need to
   explain every verdict, not just produce a score.
3. It runs on a normal laptop in milliseconds. No GPU needed.

---

## Part 3: How the model learned

Three stages.

### Stage 1: Collect examples with known answers

We gathered **1,797 real packages**:

- **898 malicious**, from a published research dataset by DataDog. These are real
  packages that genuinely attacked people and were caught.
- **899 clean**, downloaded live from npm and PyPI. These are real popular
  libraries like express, flask and requests.

The clean ones being **real libraries** matters. If we had used simple toy
examples as our "clean" set, the model would just learn to tell simple code from
complex code. Real libraries also make network calls and run subprocesses, so the
model is forced to learn the actual difference.

### Stage 2: Turn each package into numbers

For every one of the 1,797 packages, we ran our analysis and produced 58 numbers.

So we end up with a big table. 1,797 rows. 58 columns of numbers, plus one column
saying malicious or clean.

### Stage 3: Let the algorithm find the patterns

We hand the table to the training algorithm. It looks for combinations of the 58
numbers that separate the two groups, and builds those hundreds of trees.

Nobody tells it "install hooks are suspicious". It works that out because
malicious packages in the data have them far more often.

**Training took about one minute.** The slow part was collecting the 1,797
packages, not the learning.

---

## Part 4: How it decides on a new package

When we scan a package the model has never seen:

1. We read its code and produce the same 58 numbers
2. The model runs those numbers through all its trees
3. Every tree votes
4. The votes combine into one score between 0 and 1

Some of the 58 things we count:

- Does it run code at install time
- Does it decode something and immediately run it
- Does it read SSH keys, cloud credentials, or browser password stores
- Does it look for cryptocurrency wallets
- Does it contact a paste site or a Discord webhook
- Is the code scrambled or minified
- How many files, how big, how many dependencies
- How close is the name to a popular package

Plus the **combination** ones, which are the most useful. Reading an environment
variable is normal. Making a web request is normal. Doing both in the same file
is what credential theft looks like.

---

## Part 5: The example that proves the model is worth having

This is the strongest thing you can say about the model.

We scanned a small test project with 7 ordinary Python packages, nothing
malicious in it.

**The rules engine flagged 6 of them as malicious or suspicious.** Including
pillow, which is the standard image library used by millions of people. It scored
pillow at 0.98, almost certainly malicious.

Why? Because pillow genuinely does use `eval`, spawns processes, and reads files.
The rules engine sees those behaviours, adds up the points, and panics.

**The model flagged 1**, and only as suspicious rather than malicious.

The model had seen 899 real libraries during training. It learned that a package
with 400 files, 30 dependencies and a long history using `eval` is a normal big
library. A package with 3 files that reads SSH keys and posts to a Discord
webhook is not.

**The rules engine cannot learn that, because a fixed points table has no idea
how big or mature the package is.** That is exactly why the machine learning
layer is there, and that comparison is how we prove it earns its place.

---

## Quick answers to likely questions

**"Where exactly is the AI or ML in this project?"**

> "In the malicious package detection. We turn each package into 58 measurements
> and a trained model scores it. The vulnerability half does not use machine
> learning at all, that is a graph search."

**"Why not a neural network or deep learning?"**

> "Three reasons. We have around 1,800 examples and deep learning needs far more.
> Trees tell us which inputs mattered, which we need because we have to explain
> every verdict. And it runs on a laptop with no GPU."

**"How do you know the model is any good?"**

> "We tested it on data it had never seen, and we compared it against a rules
> engine using the same information. The rules engine got 0.57, the model got
> 0.95. Without that comparison, saying we used machine learning would prove
> nothing."

**"What are precision and recall?"**

> "Precision is how often we are right when we say something is malicious. Recall
> is how much of the actual malware we catch. F1 combines both into one number
> where 1.0 would be perfect."

**"Does the model download and run the packages?"**

> "It downloads them but never runs them. We read the code as text and parse it
> into a tree structure, the same way the language itself reads it. Building that
> tree never executes anything."

**"What if an attacker knows how your model works?"**

> "That is a real limitation and it applies to every detector in this field. They
> could try to look like a big mature library. That is partly why we also keep the
> combination signals, since some behaviours are very hard to hide if you actually
> want to steal credentials. It is in our future work."

---

## The 30 second version

If you get asked to explain the whole thing quickly:

> "We read the project's dependency list, expand it to everything that actually
> gets installed, and then do two things.
>
> First we read each package's code without running it, turn what it does into 58
> measurements, and a trained model scores how likely it is to be malicious.
>
> Second we take the list of publicly known bugs in those packages and check
> which ones our code can actually reach, by building a map of which function
> calls which. On our test project that took 92 reported issues down to 3 that
> genuinely matter."
