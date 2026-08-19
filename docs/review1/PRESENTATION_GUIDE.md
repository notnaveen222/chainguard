# Slide by slide guide

For the progress deck, `ChainGuard_Review1_Progress.pptx`. 15 slides.

For each slide: what it means, what to say, and what they might ask.

---

## First, the words you will need

Learn these five and you can answer almost anything.

**Package (or dependency).** A piece of code written by someone else that your
project uses. Like `requests` in Python or `express` in JavaScript.

**Transitive dependency.** The packages your packages need. You install 20, but
those 20 need others, and you end up with 1,000.

**Install hook.** Code that runs automatically the moment you install a package,
before you have used it for anything. In npm it is called `postinstall`. In
Python it is `setup.py`. This is where most attacks happen.

**CVE.** A publicly recorded security bug in a piece of software. Each has an ID
like CVE-2020-14343.

**Reachability.** Can your code actually get to the buggy function. This is the
core idea of our whole project.

---

## Slide 1: Title

**What it means.** The name of the project and what it does.

**What to say.**

> "Our project is called ChainGuard. When you build software today, most of the
> code comes from packages other people wrote. We scan those packages for two
> things. One, is any of them actually malicious. Two, out of all the known
> security bugs in them, which ones can our code actually reach.
>
> This review covers our design. We have also built a working prototype of the
> main engine to check the design holds up."

That last line matters. It sets expectations that this is design plus prototype,
not a finished product.

---

## Slide 2: Nobody writes their whole application any more

**What it means.** This explains the size of the problem. Three numbers on the
left, four reasons on the right.

**What to say.**

> "A normal Node.js project installs over a thousand packages. A Python project
> installs two to four hundred. Every one of them runs with the same permissions
> you have on your machine.
>
> Four things make this easy to attack. First, code runs the moment you install,
> before you have used the package. Second, when you trust one package you are
> also trusting everything it depends on. Third, anyone can publish to these
> registries, there is no review. Fourth, names are easy to confuse. Very few
> people notice the difference between python-dateutil and python-dateutils."

**If they ask "why does code run at install time at all?"**
Because packages sometimes need to set themselves up, for example compiling
something for your operating system. It is a useful feature that attackers abuse.

---

## Slide 3: This keeps happening to real projects

**What it means.** Five real attacks. Proof this is not theoretical.

**What to say.** Pick one and tell it as a story. `event-stream` is the easiest:

> "In 2018 a developer maintaining a popular package got tired of it and handed
> it to someone who offered to help. That person added code that stole Bitcoin
> wallets. The package had two million downloads a week before anyone noticed."

Then point at the box at the bottom:

> "None of these were clever hacks. They used the system exactly as designed."

**If they ask about XZ Utils.** Someone spent two years being a helpful
contributor to build trust, then slipped in a backdoor. It was caught by accident
by an engineer who noticed his login was half a second slower than usual.

---

## Slide 4: Two different problems

**What it means.** Our project solves two separate things. This slide keeps them
apart so the panel understands the scope.

**What to say.**

> "There are two different problems here.
>
> Problem A is packages that are malicious on purpose. Antivirus does not help,
> because every malicious package is brand new and most get removed within days.
> By the time anyone writes a signature for it, the damage is done. So we have to
> detect it by what the code does, not by recognising a known file.
>
> Problem B is different. These are ordinary packages with publicly known bugs.
> The problem is not finding them, it is that scanners report two or three hundred
> of them on a normal project. Nobody can go through three hundred items, so most
> teams go through none. And under five percent of them are in code the
> application actually calls."

**If they ask which is harder.** Problem B is harder technically, because it
needs us to understand how the code flows. Problem A is more about good features.

---

## Slide 5: What we set out to build

**What it means.** The formal problem statement on the left, and our five
objectives on the right with a status tag on each.

**What to say.**

> "Formally, given a project and all the packages it installs, we want to do two
> things. Decide whether each package is malicious without ever running it. And
> for each known bug, decide whether our code can reach it, and show the path that
> proves it.
>
> One rule matters a lot. When we are not sure whether something is reachable, we
> report it as reachable. Raising one extra alert costs a developer ten minutes.
> Missing a real vulnerability could cost a company everything."

Then point at the tags on the right:

> "Two of our five objectives are done, two are in progress, and the last one is
> what we are working towards."

**If they ask "why not just run the package in a sandbox and watch it?"**
Good question, and some research does that. Two problems. It needs a lot of
infrastructure. And smart malware waits, so it does nothing while it is being
watched and activates later. We chose static analysis, which means reading the
code without running it.

---

## Slide 6: We read 27 papers

**What it means.** Proves we did the literature review. The bar chart shows how
the papers split across five topics. The right side is what we learned.

**What to say.**

> "We reviewed 27 papers, 24 of them from 2023 onwards. They split into five
> areas, shown on the chart.
>
> Four things stood out. Everyone has moved away from signature matching to
> looking at behaviour. There are three approaches with a clear trade off, which
> I will come back to. Attackers are hiding better, use of evasion tricks grew
> almost four times between 2020 and 2025. And datasets are the bottleneck, the
> most cited dataset in this field still has only 174 samples."

**If they ask about the 2026 papers.** They are real. We checked every single
citation against the arXiv database for the correct title, authors and date
before putting it in.

**If they ask about the three approaches.** Static analysis, which is reading the
code, is fast and cheap and easy to measure. Sandboxing sees more but gets
evaded. Large language models generalise well but are slow, expensive, and the
papers keep saying it is hard to get consistent scores out of them.

---

## Slide 7: The papers that shaped our design

**What it means.** Six specific papers, what we took from each, and where each
one stops. The "where it stops" column is the important one, because those gaps
are what our project fills.

**What to say.**

> "These six shaped our design most. Samaana 2024 is closest to what we are
> doing, classical machine learning over static features. But it only covers
> Python, and it does not do reachability at all.
>
> Foo 2019 is the one that frames our whole second half. They said back in 2019
> that software composition analysis needs three things, and one of them is
> checking reachability to remove false positives. They never released an
> implementation.
>
> And the last row is a 2025 review of forty studies that still lists false
> positives as a top problem. So that is six years, and the gap is still open."

**If they ask which paper we are closest to.** Samaana 2024. We differ in three
ways: we cover npm as well as Python, we look at combinations of behaviours
rather than single features, and we add the whole reachability half.

---

## Slide 8: Four gaps

**What it means.** The four holes we found in the research, and what we plan to
do about each. This connects the literature review to our own design.

**What to say.**

> "We found four gaps.
>
> G1, detection and prioritisation are always studied separately. No paper we
> read does both, but a real developer needs both on the same project.
>
> G2 is the big one. Reachability keeps getting recommended but almost nobody
> builds it for npm and Python, because the security advisories for these
> ecosystems usually do not say which function is affected.
>
> G3, papers often skip the details of how they tested. Things like whether the
> same package appeared in both training and testing data.
>
> G4, everyone claims their tool is explainable, but most just give you a score
> and nothing else."

---

## Slide 9: The design, how a scan will run

**What it means.** The five steps of a scan, left to right, each with a status
tag showing how far along we are.

**What to say.**

> "A scan runs in five steps.
>
> First we read the project's dependency file. Second we work out the full tree,
> including everything the dependencies themselves need. Third we download each
> package and read its code to score it. Fourth we ask OSV.dev, which is Google's
> public vulnerability database, which of these versions have known bugs. Fifth we
> build a map of our own code and check which of those bugs we can actually reach.
>
> Steps one, two and four are solid. Steps three and five are the research heavy
> parts and are still being refined."

Point at the two boxes at the bottom:

> "These two are the two halves of the project, and they run independently. If one
> fails, the other still gives you a result."

---

## Slide 10: Finding malicious packages without running them

**What it means.** How our detection works. Left side is the technique, right
side is the clever bit.

**What to say, left side.**

> "We do not search the file for dangerous words. If you search for the text
> 'eval', you also match a comment, or a variable called evaluate. Instead we
> parse the file into a tree structure, the same way the language itself
> understands it.
>
> Parsing also handles renaming. If someone writes 'import subprocess as sp' and
> then calls 'sp.run', a text search sees nothing. In a tree it is obvious.
>
> And parsing is what makes this safe. Building a tree never runs the file."

**What to say, right side. This is the important part.**

> "Here is the idea we are testing. Reading an environment variable is completely
> normal, thousands of packages do it. Making a web request is normal too. But
> doing both in the same file is what credential theft looks like.
>
> So we check each file on its own first, then look for combinations across the
> whole package. No single detector can see that, because it needs two separate
> observations put together.
>
> We tested this on twelve popular real packages including express, axios, flask
> and requests. None of them triggered a combination."

**If they ask "does it just look for known bad package names?"**
No. Name similarity is only four of our features out of fifty eight. Most of what
we look at is behaviour.

---

## Slide 11: Which vulnerabilities actually matter

**What it means.** This is the heart of the project. Left side is the four
possible answers. Right side is a real example.

**What to say.**

> "We build a map of which function calls which, in the project's own code. Then
> we start from where the program actually begins and search for a path to the
> vulnerable function.
>
> We give one of four answers, not just yes or no, because the confidence really
> differs.
>
> Not imported means the package is installed but our code never even imports it.
> That is the strongest answer we can give.
>
> Symbol not called means we do import it, but never touch the specific function
> with the bug.
>
> Reachable means there is a real path, and we show it.
>
> Assumed reachable means the advisory did not say which function is affected, so
> we cannot rule it out and we report it to be safe."

Then point at the black box:

> "Here is a real one from our test project. There is a known bug in PyYAML. Our
> code reaches it in four steps across three files, and we show every step with
> the file and line number. A text search could never produce that."

Then the box at the bottom:

> "This works for Python today. For npm we can currently only tell whether a
> package is imported, not whether the specific function is called. That is our
> next big piece of work."

**If they ask "can reachability be wrong?"**
Yes. If code decides which function to call while it is running, we cannot follow
that. Which is exactly why anything uncertain is reported as reachable.

---

## Slide 12: How we will know whether it works

**What it means.** How we test honestly. The red box is a mistake we caught and
fixed. **This slide is your strongest one.**

**What to say.** Say the red box confidently, it shows real understanding.

> "We nearly made a serious mistake here.
>
> Our malicious samples come from a research archive. Those packages were removed
> from the internet years ago, so they have no live registry information. Our
> clean samples we downloaded today, so they have all of it.
>
> If we had given that information to the model, then a simple rule like 'version
> count is greater than zero' would separate the two groups perfectly. The model
> would score almost a hundred percent, but it would just be learning which folder
> a sample came from. It would be completely useless on anything real.
>
> So we remove those five fields from every training sample, in the code that
> builds the dataset, where nothing can skip it."

Then the right side:

> "The rest of our plan. We split by package, so two versions of the same package
> can never end up on both sides. We compare against a simple rules engine with no
> learning, because otherwise saying we used machine learning proves nothing. We
> remove each group of features and retrain to see what each contributes. And the
> last one, testing on real open source projects, is still ahead of us."

**If they ask what data leakage is.** It is when information sneaks into training
that would not be available in real use, so the model looks great in testing and
fails in reality.

---

## Slide 13: How the system is put together

**What it means.** Five layers, each using the one below. The right column is how
we protect the scanner itself.

**What to say.**

> "Five layers. At the top what the user sees. Below that the service that
> handles a scan request and reports progress, because a scan takes time. Then
> the analysis layer, the parsers and the model and the call graph engine. Below
> that the layer that fetches packages from npm and PyPI. And storage at the
> bottom.
>
> The right hand column matters. We deliberately download and open malicious
> files, so our own scanner is a target. We never run anything. We cap file sizes
> so a compressed bomb cannot crash us. We block files that try to escape to
> other folders on the disk. And we escape package names in reports, because an
> attacker chooses those names."

**If they ask about a zip bomb.** A small compressed file that expands to
something enormous to exhaust memory. We check the expansion ratio before
unpacking, not after.

---

## Slide 14: The modules

**What it means.** All the pieces, in four groups, each with a status tag.

**What to say.** Do not read them out. Say:

> "These are our modules in four groups. Getting packages is largely done. Reading
> the code is mostly done, with the JavaScript side still being extended. Learning
> and deciding is where most of the remaining work sits. Delivering results is
> working but being refined.
>
> The important design decision is at the bottom. Detection and reachability are
> kept separate on purpose, so if one has a problem the other still returns
> something useful."

---

## Slide 15: What is working and what comes next

**What it means.** Early numbers on the left, and the plan for Reviews 2 and 3 on
the right.

**What to say.**

> "Some early numbers. We built a first dataset of 1,797 packages, about half
> malicious and half clean. On that run our model scored 0.95 on F1, which is a
> combined measure of precision and recall. The simple rules engine scored 0.57 on
> the same data, so the learning is doing real work.
>
> And on our own test project, reachability took 92 reported vulnerabilities down
> to 3 that our code can actually reach.
>
> I want to be clear that these are first numbers from one dataset and one test
> project. They tell us the approach is worth continuing. They do not tell us the
> system is finished."

Then the remaining work, then the roadmap:

> "For Review 2 we want symbol level reachability for npm, a much bigger database
> of which functions are vulnerable, and testing on real open source projects. For
> Review 3, running inside CI so it checks every code change automatically,
> offline mode, and the final write up."

**If they ask what F1 means.** It combines two things. Precision is how often we
are right when we say something is malicious. Recall is how much of the actual
malware we catch. F1 balances both in one number, and 1.0 would be perfect.

---

## The five questions most likely to come up

**1. "Why not just use ChatGPT for this?"**

> "We did look at that closely, there are five papers on it in our review. The
> problem is that you cannot report precision and recall for a prompt reliably.
> The papers themselves say the results are unstable. We do use a language model,
> but only to write explanations of a verdict in plain English, never to make the
> decision."

**2. "Is this not the same as Snyk or Dependabot?"**

> "Those tools tell you which packages have known bugs. They do not tell you
> whether your code can reach them. The commercial tools that do reachability keep
> it proprietary, and the academic work has been recommending it since 2019
> without anyone building it openly for npm and Python."

**3. "You have real malware on your laptop, is that safe?"**

> "Nothing is ever run. We only read the code as text. The samples are stored in
> an encoded form so nothing on disk is a working program, and we decode them in
> memory only when we analyse them."

**4. "How do you know your model is not just memorising?"**

> "Two things. We split by package name, so two versions of the same package can
> never be in both training and testing. And every number we report comes from
> testing on data the model had not seen."

**5. "What does not work yet?"**

Answer this one immediately, do not hedge.

> "Three things. npm reachability is only at the import level, we cannot yet tell
> which function is called. Our database of vulnerable functions only covers about
> 35 packages, so a lot of findings come back as assumed reachable. And our model
> misses 55 out of 898 malicious samples, and we want to understand why."

---

## Practical tips

**If you do not know an answer**, say so and offer what you do know. "I have not
tested that specific case, but the way it would work is..." A panel respects that
far more than a guess.

**Do not read the slides.** They can read. Say the thing behind the slide.

**Your two strongest moments** are the data leakage story on slide 12 and the
call path on slide 11. Slow down on both.

**If you are running out of time**, skip slides 7 and 14. Never skip 11 or 12.

**Numbers to remember:** 27 papers, 1,797 packages, F1 0.95 against 0.57 for the
baseline, and 92 vulnerabilities down to 3.
