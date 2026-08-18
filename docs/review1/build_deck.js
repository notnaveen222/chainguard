/* ChainGuard - Review 1 deck generator */
const pptxgen = require('pptxgenjs');

const P = {
  dark:    '0F2A38',
  darker:  '0A1E29',
  white:   'FFFFFF',
  panel:   'EEF3F5',
  panel2:  'E2EAEE',
  accent:  '12B886',
  accentD: '0B7A5A',
  alert:   'D64545',
  amber:   'C88A1E',
  body:    '1B2A33',
  muted:   '5A6B78',
  onDark:  'DCE7EC',
  onDarkM: '8FA6B2',
};

const SERIF = 'Cambria';
const SANS  = 'Calibri';

const pres = new pptxgen();
pres.layout = 'LAYOUT_WIDE';           // 13.3 x 7.5
pres.author = 'ChainGuard';
pres.title  = 'ChainGuard - Review 1';

const W = 13.3, H = 7.5, M = 0.65;

/* ---------- helpers ---------- */

// Rubric marker: numbered square + label. Repeated motif on every content slide.
function rubric(slide, num, label, onDark) {
  slide.addShape(pres.ShapeType.rect, {
    x: M, y: 0.42, w: 0.34, h: 0.34,
    fill: { color: P.accent },
  });
  slide.addText(num, {
    x: M, y: 0.42, w: 0.34, h: 0.34,
    fontFace: SANS, fontSize: 13, bold: true, color: P.white,
    align: 'center', valign: 'middle', margin: 0,
  });
  slide.addText(label.toUpperCase(), {
    x: M + 0.46, y: 0.42, w: 6, h: 0.34,
    fontFace: SANS, fontSize: 10.5, bold: true,
    color: onDark ? P.onDarkM : P.muted,
    charSpacing: 1.6, valign: 'middle', margin: 0,
  });
}

function title(slide, text, onDark) {
  slide.addText(text, {
    x: M, y: 0.92, w: W - M * 2, h: 0.72,
    fontFace: SERIF, fontSize: 30, bold: true,
    color: onDark ? P.white : P.body,
    valign: 'middle', margin: 0,
  });
}

function card(slide, o) {
  slide.addShape(pres.ShapeType.roundRect, {
    x: o.x, y: o.y, w: o.w, h: o.h,
    fill: { color: o.fill || P.panel },
    line: { color: o.line || P.panel2, width: 1 },
    rectRadius: 0.06,
  });
}

function pageNum(slide, n) {
  slide.addText(String(n), {
    x: W - M - 0.5, y: H - 0.55, w: 0.5, h: 0.3,
    fontFace: SANS, fontSize: 9, color: P.muted,
    align: 'right', margin: 0,
  });
}

/* ================= 1. TITLE ================= */
{
  const s = pres.addSlide();
  s.background = { color: P.dark };

  s.addText('FINAL YEAR PROJECT   |   REVIEW 1', {
    x: M, y: 1.5, w: 10, h: 0.3,
    fontFace: SANS, fontSize: 11, bold: true, color: P.accent,
    charSpacing: 2.2, margin: 0,
  });

  s.addText('ChainGuard', {
    x: M, y: 1.95, w: 11, h: 1.15,
    fontFace: SERIF, fontSize: 54, bold: true, color: P.white, margin: 0,
  });

  s.addText('AI-Powered Software Supply Chain Security', {
    x: M, y: 3.05, w: 11, h: 0.45,
    fontFace: SERIF, fontSize: 21, color: P.onDark, margin: 0,
  });
  s.addText('Malicious Package Detection and Vulnerability Reachability Analysis', {
    x: M, y: 3.5, w: 11, h: 0.4,
    fontFace: SANS, fontSize: 14, color: P.onDarkM, margin: 0,
  });

  const items = [
    ['01', 'Domain and Problem'],
    ['02', 'Literature Review'],
    ['03', 'Proposed Methodology'],
    ['04', 'Module and System Design'],
  ];
  items.forEach(([n, t], i) => {
    const x = M + i * 3.05;
    s.addText(n, {
      x, y: 4.75, w: 2.8, h: 0.36,
      fontFace: SANS, fontSize: 15, bold: true, color: P.accent, margin: 0,
    });
    s.addText(t, {
      x, y: 5.1, w: 2.8, h: 0.36,
      fontFace: SANS, fontSize: 12.5, color: P.onDark, margin: 0,
    });
  });

  s.addText('Scans a project, finds packages that are actually malicious, and works out which known vulnerabilities the code can really reach.', {
    x: M, y: 6.35, w: 11.4, h: 0.4,
    fontFace: SANS, fontSize: 12, italic: true, color: P.onDarkM, margin: 0,
  });
  s.addNotes('Introduce the project in one line: we scan a dependency tree, flag packages that are actually malicious, and cut the CVE list down to the ones the application can really reach.');
}

/* ================= 2. DOMAIN ================= */
{
  const s = pres.addSlide();
  rubric(s, '01', 'Domain and Problem Statement');
  title(s, 'Nobody writes their whole application any more');

  const stats = [
    ['1,000+', 'packages installed by\na typical Node project'],
    ['200-400', 'packages installed by\na typical Python project'],
    ['Full', 'privileges each one gets\non your machine'],
  ];
  stats.forEach(([v, k], i) => {
    const y = 1.85 + i * 1.42;
    card(s, { x: M, y, w: 5.1, h: 1.22 });
    s.addText(v, {
      x: M + 0.28, y: y + 0.14, w: 2.0, h: 0.6,
      fontFace: SERIF, fontSize: 30, bold: true, color: P.accentD, margin: 0, valign: 'middle',
    });
    s.addText(k, {
      x: M + 2.3, y: y + 0.14, w: 2.6, h: 0.95,
      fontFace: SANS, fontSize: 12, color: P.body, margin: 0, valign: 'middle',
    });
  });

  s.addText('Why it is easy to attack', {
    x: 6.35, y: 1.85, w: 6.3, h: 0.36,
    fontFace: SANS, fontSize: 13, bold: true, color: P.body,
    charSpacing: 0.8, margin: 0,
  });

  const reasons = [
    ['Code runs when you install', 'npm postinstall hooks and Python setup.py execute before you have run anything yourself.'],
    ['You inherit every dependency', 'Trusting one package means trusting its whole tree, and every maintainer in it.'],
    ['Anyone can publish', 'No review. Names are handed out first come, first served.'],
    ['Names are easy to confuse', 'Very few people spot the difference between python-dateutil and python-dateutils.'],
  ];
  reasons.forEach(([h, d], i) => {
    const y = 2.3 + i * 1.09;
    s.addShape(pres.ShapeType.ellipse, {
      x: 6.35, y: y + 0.04, w: 0.26, h: 0.26, fill: { color: P.accent },
    });
    s.addText(h, {
      x: 6.75, y, w: 5.9, h: 0.32,
      fontFace: SANS, fontSize: 12.5, bold: true, color: P.body, margin: 0,
    });
    s.addText(d, {
      x: 6.75, y: y + 0.31, w: 5.9, h: 0.62,
      fontFace: SANS, fontSize: 11, color: P.muted, margin: 0,
    });
  });

  pageNum(s, 2);
  s.addNotes('The point to land: most of the code you ship, you did not write. And it runs with your privileges at install time.');
}

/* ================= 3. INCIDENTS ================= */
{
  const s = pres.addSlide();
  rubric(s, '01', 'Domain and Problem Statement');
  title(s, 'This keeps happening to real projects');

  const rows = [
    [{ text: 'Package', options: { bold: true } }, { text: 'Year', options: { bold: true } }, { text: 'How it got in', options: { bold: true } }, { text: 'What it did', options: { bold: true } }],
    ['event-stream', '2018', 'Maintainer handed it to a stranger', 'Stole Bitcoin wallets. 2M a week.'],
    ['ua-parser-js', '2021', 'Maintainer account was compromised', 'Cryptominer and password stealer'],
    ['ctx', '2022', 'Abandoned package name was taken over', 'Sent AWS keys to the attacker'],
    ['torchtriton', '2022', 'Dependency confusion against PyTorch', 'Uploaded SSH keys and /etc/passwd'],
    ['XZ Utils', '2024', 'Two years of social engineering', 'Almost backdoored SSH everywhere'],
  ];

  s.addTable(rows, {
    x: M, y: 1.85, w: W - M * 2,
    colW: [2.1, 0.85, 4.5, 4.55],
    fontFace: SANS, fontSize: 11.5, color: P.body,
    border: { type: 'solid', color: P.panel2, pt: 1 },
    fill: { color: P.white },
    rowH: 0.52, valign: 'middle',
    margin: [0.06, 0.12, 0.06, 0.12],
  });

  card(s, { x: M, y: 5.55, w: W - M * 2, h: 0.92, fill: P.panel });
  s.addText('None of these were clever zero days. They were the normal way the ecosystem works, turned against the people using it.', {
    x: M + 0.3, y: 5.55, w: W - M * 2 - 0.6, h: 0.92,
    fontFace: SANS, fontSize: 13, color: P.body, valign: 'middle', margin: 0,
  });

  pageNum(s, 3);
  s.addNotes('Use one of these as the story. event-stream is the easiest to explain: a maintainer got tired, handed the project over, and the new owner added a wallet stealer.');
}

/* ================= 4. TWO PROBLEMS ================= */
{
  const s = pres.addSlide();
  rubric(s, '01', 'Domain and Problem Statement');
  title(s, 'Two different problems, and both are unsolved');

  const cols = [
    {
      x: M, tag: 'PROBLEM A', tagColor: P.alert,
      head: 'Some packages are malicious on purpose',
      pts: [
        'The payload usually runs at install time and steals credentials, wallets or SSH keys.',
        'Antivirus does not help. Every malicious package is brand new, and most are taken down within days.',
        'By the time a signature exists, the damage is done.',
      ],
      foot: 'So detection has to work from behaviour, not from a list of known bad files.',
    },
    {
      x: 7.0, tag: 'PROBLEM B', tagColor: P.amber,
      head: 'Vulnerability reports are too noisy to use',
      pts: [
        'Scanners match versions against a CVE database and report every hit. A real project gets 150 to 300 findings.',
        'Nobody can triage 300 items, so most teams triage none of them.',
        'Under 5% of those CVEs are in code the application actually calls.',
      ],
      foot: 'So the job is not finding more issues. It is working out which ones matter.',
    },
  ];

  cols.forEach((c) => {
    card(s, { x: c.x, y: 1.8, w: 5.65, h: 4.55, fill: P.white, line: P.panel2 });
    s.addText(c.tag, {
      x: c.x + 0.35, y: 2.0, w: 3, h: 0.28,
      fontFace: SANS, fontSize: 10.5, bold: true, color: c.tagColor,
      charSpacing: 1.8, margin: 0,
    });
    s.addText(c.head, {
      x: c.x + 0.35, y: 2.32, w: 4.95, h: 0.75,
      fontFace: SERIF, fontSize: 17, bold: true, color: P.body, margin: 0,
    });
    s.addText(
      c.pts.map((t, i) => ({ text: t, options: { bullet: true, breakLine: i < c.pts.length - 1 } })),
      {
        x: c.x + 0.35, y: 3.15, w: 4.95, h: 2.0,
        fontFace: SANS, fontSize: 12, color: P.body,
        paraSpaceAfter: 8, margin: 0,
      }
    );
    s.addText(c.foot, {
      x: c.x + 0.35, y: 5.42, w: 4.95, h: 0.7,
      fontFace: SANS, fontSize: 11.5, italic: true, color: P.accentD, margin: 0,
    });
  });

  pageNum(s, 4);
  s.addNotes('Stress that these are different kinds of problem. A is detection, B is prioritisation. Most tools do one or the other.');
}

/* ================= 5. PROBLEM STATEMENT ================= */
{
  const s = pres.addSlide();
  s.background = { color: P.dark };
  rubric(s, '01', 'Domain and Problem Statement', true);
  title(s, 'What we set out to build', true);

  s.addShape(pres.ShapeType.roundRect, {
    x: M, y: 1.8, w: 6.6, h: 3.95,
    fill: { color: P.darker }, line: { color: '1E3D4D', width: 1 }, rectRadius: 0.06,
  });
  s.addText('PROBLEM STATEMENT', {
    x: M + 0.35, y: 2.0, w: 5, h: 0.28,
    fontFace: SANS, fontSize: 10.5, bold: true, color: P.accent, charSpacing: 1.8, margin: 0,
  });
  s.addText(
    [
      { text: 'Given a project and the full set of packages it installs:', options: { breakLine: true, bold: true } },
      { text: '\n', options: { breakLine: true } },
      { text: 'A.  Decide whether each package is malicious, without ever running it, and show the evidence behind the decision.', options: { breakLine: true } },
      { text: '\n', options: { breakLine: true } },
      { text: 'B.  For every known vulnerability, decide whether the application can actually reach the vulnerable function, and show the call path that proves it.', options: { breakLine: true } },
      { text: '\n', options: { breakLine: true } },
      { text: 'When we are not sure in B, we report it as reachable. Missing a real vulnerability is far worse than raising one extra alert.', options: { italic: true } },
    ],
    {
      x: M + 0.35, y: 2.38, w: 5.9, h: 3.2,
      fontFace: SANS, fontSize: 12, color: P.onDark, lineSpacing: 17, margin: 0,
    }
  );

  s.addText('Objectives', {
    x: 7.75, y: 1.9, w: 5, h: 0.35,
    fontFace: SANS, fontSize: 13, bold: true, color: P.white, margin: 0,
  });
  const objs = [
    'Pull apart Python and JavaScript packages without running them',
    'Train a classifier on real malware and real libraries, and test it properly',
    'Build a call graph that separates vulnerabilities that matter from ones that do not',
    'Measure how much noise the reachability step actually removes',
    'Ship it as something usable: an API, a dashboard and a command line tool',
  ];
  objs.forEach((t, i) => {
    const y = 2.38 + i * 0.72;
    s.addText(String(i + 1), {
      x: 7.75, y, w: 0.3, h: 0.3,
      fontFace: SANS, fontSize: 12, bold: true, color: P.accent, margin: 0,
    });
    s.addText(t, {
      x: 8.12, y: y - 0.03, w: 4.5, h: 0.66,
      fontFace: SANS, fontSize: 11.5, color: P.onDark, margin: 0,
    });
  });

  pageNum(s, 5);
  s.addNotes('The fail safe rule in the box is worth saying out loud. If we cannot tell, we report it. A false alarm costs ten minutes, a miss ships a vulnerability.');
}

/* ================= 6. LITERATURE SCOPE ================= */
{
  const s = pres.addSlide();
  rubric(s, '02', 'Literature Review');
  title(s, 'We read 27 papers, 24 of them from 2023 onwards');

  s.addChart(
    pres.ChartType.bar,
    [{
      name: 'Papers',
      labels: ['Threats and datasets', 'ML detection', 'LLM approaches', 'Reachability and SCA', 'SBOM and provenance'],
      values: [8, 7, 5, 4, 3],
    }],
    {
      x: M, y: 1.8, w: 6.6, h: 3.6,
      barDir: 'bar',
      chartColors: [P.accentD],
      showValue: true, dataLabelPosition: 'outEnd',
      dataLabelColor: P.body, dataLabelFontFace: SANS, dataLabelFontSize: 11,
      catAxisLabelColor: P.body, catAxisLabelFontFace: SANS, catAxisLabelFontSize: 11,
      valAxisLabelColor: P.muted, valAxisLabelFontFace: SANS, valAxisLabelFontSize: 10,
      valGridLine: { color: P.panel2, size: 1 },
      catGridLine: { style: 'none' },
      showLegend: false, showTitle: false,
      valAxisMaxVal: 10,
    }
  );

  s.addText('What the field agrees on', {
    x: 7.6, y: 1.85, w: 5.05, h: 0.35,
    fontFace: SANS, fontSize: 13, bold: true, color: P.body, margin: 0,
  });

  const findings = [
    ['Everyone moved to behaviour', 'Signature matching is gone. Detectors now look at what a package does, not what it looks like.'],
    ['Three approaches, one trade off', 'Static ML is cheap and measurable. Sandboxes see more but get evaded. LLMs generalise well but are slow and hard to score.'],
    ['Attackers are hiding better', 'Use of evasion tricks grew 3.8 times between 2020 and 2025.'],
    ['Datasets are the bottleneck', 'The most cited dataset still has only 174 samples.'],
  ];
  findings.forEach(([h, d], i) => {
    const y = 2.3 + i * 1.05;
    s.addText(h, {
      x: 7.6, y, w: 5.05, h: 0.3,
      fontFace: SANS, fontSize: 12, bold: true, color: P.accentD, margin: 0,
    });
    s.addText(d, {
      x: 7.6, y: y + 0.29, w: 5.05, h: 0.72,
      fontFace: SANS, fontSize: 10.5, color: P.muted, margin: 0,
    });
  });

  card(s, { x: M, y: 5.7, w: 6.6, h: 0.72, fill: P.panel });
  s.addText('Every paper was checked against the arXiv API for title, authors and date before we cited it.', {
    x: M + 0.28, y: 5.7, w: 6.05, h: 0.72,
    fontFace: SANS, fontSize: 11, italic: true, color: P.body, valign: 'middle', margin: 0,
  });

  pageNum(s, 6);
  s.addNotes('If asked about the 2026 papers: they are real, verified through the arXiv API before citing.');
}

/* ================= 7. KEY PAPERS ================= */
{
  const s = pres.addSlide();
  rubric(s, '02', 'Literature Review');
  title(s, 'The papers that shaped our design');

  const rows = [
    [
      { text: 'Paper', options: { bold: true } },
      { text: 'What it gave us', options: { bold: true } },
      { text: 'Where it stops', options: { bold: true } },
    ],
    ['Ohm et al. 2020\nBackstabber’s Knife Collection', 'The first real dataset of supply chain attacks. Showed install hooks are the main way payloads run.', 'Only 174 samples, and it predates the recent jump in volume.'],
    ['Zimmermann et al. 2019\nSmall World with High Risks', 'Measured how far trust spreads. A few npm accounts can reach most of the ecosystem.', 'Describes the structure. Does not detect anything.'],
    ['Samaana et al. 2024\nML for malicious PyPI packages', 'Closest work to ours. Classical ML over static features.', 'PyPI only, and no reachability. Notes that edit distance alone gives poor typosquat results.'],
    ['Zahan et al. 2024\nLLMs to detect npm malware', 'Showed LLMs can spot malicious packages.', 'Slow, costly, and hard to report stable precision and recall.'],
    ['Foo et al. 2019\nDynamics of Software Composition Analysis', 'Named reachability as the way to kill false positives in SCA.', 'No implementation was released.'],
    ['O’Donoghue et al. 2025\nSBOM systematic review', 'Reviewed 40 studies. False positives are still a top barrier.', 'Confirms the problem is open. Does not solve it.'],
  ];

  s.addTable(rows, {
    x: M, y: 1.8, w: W - M * 2,
    colW: [3.5, 4.3, 4.2],
    fontFace: SANS, fontSize: 10, color: P.body,
    border: { type: 'solid', color: P.panel2, pt: 1 },
    fill: { color: P.white },
    rowH: 0.6, valign: 'middle',
    margin: [0.06, 0.12, 0.06, 0.12],
  });

  pageNum(s, 7);
  s.addNotes('If they ask which paper is closest: Samaana 2024. We differ by covering npm too, by using co-occurrence signals, and by adding the whole reachability half.');
}

/* ================= 8. GAP ================= */
{
  const s = pres.addSlide();
  rubric(s, '02', 'Literature Review');
  title(s, 'Four gaps we found, and what we did about each');

  const gaps = [
    ['G1', 'Detection and prioritisation are studied separately', 'No paper we read does both. A developer needs both on the same project.', 'One pipeline runs both over the same dependency tree.'],
    ['G2', 'Reachability is recommended but rarely built for npm and PyPI', 'Advisories for these ecosystems almost never say which function is vulnerable.', 'We pull symbols from three sources and report which one was used.'],
    ['G3', 'Evaluation details are usually missing', 'Grouping, leakage and baselines are rarely discussed, so results are hard to trust.', 'Grouped splits, a rules baseline, and leakage removed by design.'],
    ['G4', 'Explainability is claimed more than delivered', 'Most detectors give a score and nothing else.', 'Every verdict carries the file, the line and the code that triggered it.'],
  ];

  gaps.forEach(([id, h, why, fix], i) => {
    const x = M + (i % 2) * 6.15;
    const y = 1.8 + Math.floor(i / 2) * 2.3;
    card(s, { x, y, w: 5.85, h: 2.05, fill: P.white, line: P.panel2 });

    s.addShape(pres.ShapeType.rect, { x: x + 0.3, y: y + 0.28, w: 0.5, h: 0.3, fill: { color: P.alert } });
    s.addText(id, {
      x: x + 0.3, y: y + 0.28, w: 0.5, h: 0.3,
      fontFace: SANS, fontSize: 11, bold: true, color: P.white,
      align: 'center', valign: 'middle', margin: 0,
    });
    s.addText(h, {
      x: x + 0.92, y: y + 0.22, w: 4.7, h: 0.45,
      fontFace: SANS, fontSize: 12.5, bold: true, color: P.body, margin: 0, valign: 'middle',
    });
    s.addText(why, {
      x: x + 0.3, y: y + 0.75, w: 5.25, h: 0.6,
      fontFace: SANS, fontSize: 10.5, color: P.muted, margin: 0,
    });
    s.addText('Our answer:  ' + fix, {
      x: x + 0.3, y: y + 1.35, w: 5.25, h: 0.55,
      fontFace: SANS, fontSize: 10.5, bold: true, color: P.accentD, margin: 0,
    });
  });

  pageNum(s, 8);
  s.addNotes('G2 is the strongest one to talk about. Reachability was recommended in 2019 and a 2025 review still lists false positives as a top barrier. Six years, same gap.');
}

/* ================= 9. PIPELINE ================= */
{
  const s = pres.addSlide();
  rubric(s, '03', 'Design of Proposed Methodology');
  title(s, 'How a scan actually runs');

  const stages = [
    ['1', 'Parse', 'Read package.json or\nrequirements.txt'],
    ['2', 'Resolve', 'Walk the full tree of\ndependencies'],
    ['3', 'Detect', 'Download, read the code,\nscore each package'],
    ['4', 'Advise', 'Ask OSV.dev which\nversions have CVEs'],
    ['5', 'Reach', 'Build a call graph and\ntest what is reachable'],
  ];

  stages.forEach(([n, h, d], i) => {
    const x = M + i * 2.46;
    card(s, { x, y: 2.0, w: 2.2, h: 2.15, fill: i >= 2 ? P.white : P.panel, line: P.panel2 });
    s.addShape(pres.ShapeType.ellipse, {
      x: x + 0.28, y: 2.24, w: 0.42, h: 0.42, fill: { color: i >= 2 ? P.accent : P.muted },
    });
    s.addText(n, {
      x: x + 0.28, y: 2.24, w: 0.42, h: 0.42,
      fontFace: SANS, fontSize: 12, bold: true, color: P.white,
      align: 'center', valign: 'middle', margin: 0,
    });
    s.addText(h, {
      x: x + 0.28, y: 2.8, w: 1.7, h: 0.35,
      fontFace: SERIF, fontSize: 15, bold: true, color: P.body, margin: 0,
    });
    s.addText(d, {
      x: x + 0.28, y: 3.16, w: 1.75, h: 0.85,
      fontFace: SANS, fontSize: 10, color: P.muted, margin: 0,
    });
    if (i < 4) {
      s.addShape(pres.ShapeType.rightArrow, {
        x: x + 2.24, y: 2.95, w: 0.2, h: 0.22, fill: { color: P.accent },
      });
    }
  });

  s.addText('Steps 3 and 5 are independent. If one fails, the other still returns a result.', {
    x: M, y: 4.35, w: 11.5, h: 0.35,
    fontFace: SANS, fontSize: 11.5, italic: true, color: P.muted, margin: 0,
  });

  card(s, { x: M, y: 4.9, w: 5.85, h: 1.55, fill: P.panel });
  s.addText('Malicious package detection', {
    x: M + 0.3, y: 5.05, w: 5.2, h: 0.3,
    fontFace: SANS, fontSize: 12, bold: true, color: P.body, margin: 0,
  });
  s.addText('Reads the code without running it, turns behaviour into 58 numbers, and a trained model scores it.', {
    x: M + 0.3, y: 5.38, w: 5.25, h: 0.9,
    fontFace: SANS, fontSize: 11, color: P.muted, margin: 0,
  });

  card(s, { x: 7.0, y: 4.9, w: 5.65, h: 1.55, fill: P.panel });
  s.addText('Vulnerability reachability', {
    x: 7.3, y: 5.05, w: 5.0, h: 0.3,
    fontFace: SANS, fontSize: 12, bold: true, color: P.body, margin: 0,
  });
  s.addText('Builds a call graph of your own code and checks whether the vulnerable function is ever called.', {
    x: 7.3, y: 5.38, w: 5.05, h: 0.9,
    fontFace: SANS, fontSize: 11, color: P.muted, margin: 0,
  });

  pageNum(s, 9);
  s.addNotes('Walk left to right once. Then point out the two branches at the bottom are the two halves of the project.');
}

/* ================= 10. DETECTION ================= */
{
  const s = pres.addSlide();
  rubric(s, '03', 'Design of Proposed Methodology');
  title(s, 'Finding malicious packages without running them');

  s.addText('We read the code, not the file', {
    x: M, y: 1.8, w: 6.0, h: 0.32,
    fontFace: SANS, fontSize: 13, bold: true, color: P.body, margin: 0,
  });
  s.addText(
    [
      { text: 'Searching for the text "eval(" also matches a comment or a variable called evaluate. So we parse the file into a syntax tree instead.', options: { bullet: true, breakLine: true } },
      { text: 'Parsing also follows renames. "import subprocess as sp" then "sp.run(...)" is invisible to a text search but obvious in a tree.', options: { bullet: true, breakLine: true } },
      { text: 'Parsing is also what makes this safe. Building a tree never executes the file.', options: { bullet: true } },
    ],
    {
      x: M, y: 2.18, w: 6.0, h: 1.65,
      fontFace: SANS, fontSize: 11.5, color: P.body, paraSpaceAfter: 7, margin: 0,
    }
  );

  card(s, { x: M, y: 3.95, w: 6.0, h: 1.15, fill: P.panel });
  s.addText('No package is ever installed or executed. Not once, anywhere in the system.', {
    x: M + 0.3, y: 3.95, w: 5.4, h: 1.15,
    fontFace: SANS, fontSize: 12.5, bold: true, color: P.accentD, valign: 'middle', margin: 0,
  });

  s.addText('The idea that makes it accurate', {
    x: 7.1, y: 1.8, w: 5.55, h: 0.32,
    fontFace: SANS, fontSize: 13, bold: true, color: P.body, margin: 0,
  });
  s.addText('Reading an environment variable is normal. Making a web request is normal. Doing both in the same file is how credential theft looks.', {
    x: 7.1, y: 2.18, w: 5.55, h: 0.75,
    fontFace: SANS, fontSize: 11.5, color: P.body, margin: 0,
  });
  s.addText('So each file is checked on its own first, then we look for combinations across the whole package. A single detector can never see that.', {
    x: 7.1, y: 2.95, w: 5.55, h: 0.75,
    fontFace: SANS, fontSize: 11.5, color: P.body, margin: 0,
  });

  card(s, { x: 7.1, y: 3.8, w: 5.55, h: 1.3, fill: P.white, line: P.accent });
  s.addText('We tested this on 12 popular real packages including express, axios, webpack, flask and requests. Not one combination signal fired. Both malicious test samples set them off straight away.', {
    x: 7.35, y: 3.8, w: 5.05, h: 1.3,
    fontFace: SANS, fontSize: 11, color: P.body, valign: 'middle', margin: 0,
  });

  const chips = ['Install hooks', 'Hidden code', 'Credential paths', 'Wallet theft', 'Typosquatting', 'Network drops'];
  chips.forEach((t, i) => {
    const x = M + i * 2.03;
    s.addShape(pres.ShapeType.roundRect, {
      x, y: 5.5, w: 1.9, h: 0.45,
      fill: { color: P.panel2 }, line: { color: P.panel2, width: 1 }, rectRadius: 0.06,
    });
    s.addText(t, {
      x, y: 5.5, w: 1.9, h: 0.45,
      fontFace: SANS, fontSize: 10, color: P.body,
      align: 'center', valign: 'middle', margin: 0,
    });
  });
  s.addText('38 things we look for, grouped into 10 kinds of behaviour', {
    x: M, y: 6.05, w: 11.5, h: 0.3,
    fontFace: SANS, fontSize: 10.5, italic: true, color: P.muted, margin: 0,
  });

  pageNum(s, 10);
  s.addNotes('The combination idea is the one to emphasise. Individually these behaviours are everywhere. Together in one file they are not.');
}

/* ================= 11. REACHABILITY ================= */
{
  const s = pres.addSlide();
  rubric(s, '03', 'Design of Proposed Methodology');
  title(s, 'Working out which vulnerabilities actually matter');

  s.addText('We build a call graph of your own code, then search from the places execution really starts, looking for a path into the vulnerable function.', {
    x: M, y: 1.78, w: 11.9, h: 0.4,
    fontFace: SANS, fontSize: 12.5, color: P.body, margin: 0,
  });

  const verdicts = [
    ['Not imported', 'The package is installed but your code never imports it.', 'High confidence', P.accentD],
    ['Symbol not called', 'You import it, but never touch the vulnerable function.', 'Medium confidence', P.accentD],
    ['Reachable', 'There is a real path to it, and here is that path.', 'Needs fixing', P.alert],
    ['Assumed reachable', 'The advisory does not say which function is affected, so we cannot rule it out.', 'Reported anyway', P.amber],
  ];
  verdicts.forEach(([h, d, c, col], i) => {
    const y = 2.35 + i * 1.0;
    card(s, { x: M, y, w: 6.6, h: 0.88, fill: P.white, line: P.panel2 });
    s.addShape(pres.ShapeType.ellipse, { x: M + 0.28, y: y + 0.31, w: 0.24, h: 0.24, fill: { color: col } });
    s.addText(h, {
      x: M + 0.68, y: y + 0.09, w: 3.2, h: 0.34,
      fontFace: SANS, fontSize: 12.5, bold: true, color: P.body, margin: 0,
    });
    s.addText(d, {
      x: M + 0.68, y: y + 0.42, w: 4.5, h: 0.4,
      fontFace: SANS, fontSize: 10.5, color: P.muted, margin: 0,
    });
    s.addText(c, {
      x: M + 5.15, y: y + 0.09, w: 1.3, h: 0.34,
      fontFace: SANS, fontSize: 9.5, bold: true, color: col, align: 'right', margin: 0,
    });
  });

  s.addText('When it is reachable, we show the proof', {
    x: 7.55, y: 2.35, w: 5.1, h: 0.32,
    fontFace: SANS, fontSize: 13, bold: true, color: P.body, margin: 0,
  });

  s.addShape(pres.ShapeType.roundRect, {
    x: 7.55, y: 2.75, w: 5.1, h: 2.15,
    fill: { color: P.darker }, line: { color: '1E3D4D', width: 1 }, rectRadius: 0.06,
  });
  s.addText(
    [
      { text: 'app.py:31   app', options: { breakLine: true } },
      { text: '  → app.main            app.py:26', options: { breakLine: true } },
      { text: '     → app.bootstrap     app.py:21', options: { breakLine: true } },
      { text: '        → load_settings  config.py:18', options: { breakLine: true } },
      { text: '           → yaml.load', options: { bold: true, color: 'FF8A7A' } },
    ],
    {
      x: 7.8, y: 2.95, w: 4.7, h: 1.75,
      fontFace: 'Courier New', fontSize: 10.5, color: P.onDark, lineSpacing: 16, margin: 0,
    }
  );

  s.addText('CVE-2020-14343 in PyYAML. Four steps from the entry point, across three files. A text search cannot produce that.', {
    x: 7.55, y: 5.0, w: 5.1, h: 0.6,
    fontFace: SANS, fontSize: 10.5, color: P.muted, margin: 0,
  });

  card(s, { x: 7.55, y: 5.65, w: 5.1, h: 0.8, fill: P.panel });
  s.addText('If we cannot tell, we say reachable. A false alarm costs ten minutes. A miss ships a live vulnerability.', {
    x: 7.8, y: 5.65, w: 4.65, h: 0.8,
    fontFace: SANS, fontSize: 10.5, italic: true, color: P.body, valign: 'middle', margin: 0,
  });

  pageNum(s, 11);
  s.addNotes('Show the call path and say it out loud. Four hops, three files. This is the artifact that convinces people it is real analysis.');
}

/* ================= 12. EVALUATION ================= */
{
  const s = pres.addSlide();
  rubric(s, '03', 'Design of Proposed Methodology');
  title(s, 'How we made sure we were not fooling ourselves');

  s.addShape(pres.ShapeType.roundRect, {
    x: M, y: 1.8, w: 6.35, h: 2.55,
    fill: { color: 'FCF0EE' }, line: { color: P.alert, width: 1 }, rectRadius: 0.06,
  });
  s.addText('THE MISTAKE WE ALMOST MADE', {
    x: M + 0.32, y: 2.0, w: 5.5, h: 0.28,
    fontFace: SANS, fontSize: 10.5, bold: true, color: P.alert, charSpacing: 1.5, margin: 0,
  });
  s.addText('Our malicious samples come from an archive, so they have no live registry data. Our clean samples were downloaded today, so they have all of it.', {
    x: M + 0.32, y: 2.35, w: 5.7, h: 0.72,
    fontFace: SANS, fontSize: 11.5, color: P.body, margin: 0,
  });
  s.addText('If we had fed that data to the model, "version count above zero" would have split the two groups perfectly. The model would score almost 100% by learning which folder a sample came from, and it would be useless on anything real.', {
    x: M + 0.32, y: 3.05, w: 5.7, h: 1.1,
    fontFace: SANS, fontSize: 11.5, color: P.body, margin: 0,
  });

  card(s, { x: M, y: 4.55, w: 6.35, h: 1.05, fill: P.panel });
  s.addText('So we strip those five fields out of every training sample, in the code that builds the dataset, where nothing can skip it.', {
    x: M + 0.32, y: 4.55, w: 5.7, h: 1.05,
    fontFace: SANS, fontSize: 11.5, bold: true, color: P.accentD, valign: 'middle', margin: 0,
  });

  s.addText('The rest of the setup', {
    x: 7.35, y: 1.85, w: 5.3, h: 0.32,
    fontFace: SANS, fontSize: 13, bold: true, color: P.body, margin: 0,
  });

  const setup = [
    ['Split by package, not by file', 'Two versions of the same package can never sit on both sides of the split. Otherwise the model just recognises what it has already seen.'],
    ['Every number is out of fold', 'No sample is ever scored by a model that was trained on it.'],
    ['We compare against a rules engine', 'Same signals, no learning. Without that comparison, saying we used machine learning proves nothing.'],
    ['We remove each group of features and retrain', 'That shows what each kind of signal is really contributing.'],
  ];
  setup.forEach(([h, d], i) => {
    const y = 2.28 + i * 1.08;
    s.addText(h, {
      x: 7.35, y, w: 5.3, h: 0.3,
      fontFace: SANS, fontSize: 11.5, bold: true, color: P.body, margin: 0,
    });
    s.addText(d, {
      x: 7.35, y: y + 0.29, w: 5.3, h: 0.75,
      fontFace: SANS, fontSize: 10.5, color: P.muted, margin: 0,
    });
  });

  pageNum(s, 12);
  s.addNotes('This slide wins marks. Volunteering the leakage problem before anyone asks shows you understand what a good result actually requires.');
}

/* ================= 13. ARCHITECTURE ================= */
{
  const s = pres.addSlide();
  rubric(s, '04', 'Module Description and System Design');
  title(s, 'How the system is put together');

  const layers = [
    ['What the user sees', 'React dashboard    Command line tool    HTML report you can print', P.accent],
    ['Handling a scan', 'FastAPI service    Background jobs with progress    Scan orchestrator', P.accentD],
    ['Doing the analysis', 'Python and JavaScript parsers    58 features    Trained model    Call graph engine', P.accentD],
    ['Getting the packages', 'npm client    PyPI client    Safe archive unpacking    Dependency resolver    OSV.dev', P.muted],
    ['Storage', 'SQLite scan history    Encoded sample store    Download cache    Saved model', P.muted],
  ];

  layers.forEach(([h, d, col], i) => {
    const y = 1.85 + i * 0.95;
    card(s, { x: M, y, w: 8.6, h: 0.82, fill: P.white, line: P.panel2 });
    s.addShape(pres.ShapeType.rect, { x: M + 0.25, y: y + 0.26, w: 0.3, h: 0.3, fill: { color: col } });
    s.addText(h, {
      x: M + 0.72, y: y + 0.06, w: 3.0, h: 0.35,
      fontFace: SANS, fontSize: 12.5, bold: true, color: P.body, margin: 0, valign: 'middle',
    });
    s.addText(d, {
      x: M + 0.72, y: y + 0.4, w: 7.6, h: 0.36,
      fontFace: SANS, fontSize: 10, color: P.muted, margin: 0, valign: 'middle',
    });
  });

  s.addText('Built to survive bad input', {
    x: 9.55, y: 1.9, w: 3.1, h: 0.32,
    fontFace: SANS, fontSize: 12.5, bold: true, color: P.body, margin: 0,
  });
  s.addText('The scanner reads hostile files on purpose, so it is a target itself.', {
    x: 9.55, y: 2.25, w: 3.1, h: 0.55,
    fontFace: SANS, fontSize: 10.5, color: P.muted, margin: 0,
  });

  const guards = [
    'Nothing is ever run',
    'Zip bombs are capped',
    'Escaping file paths blocked',
    'Parser has a time limit',
    'Package names escaped in reports',
  ];
  guards.forEach((t, i) => {
    const y = 2.9 + i * 0.62;
    s.addShape(pres.ShapeType.ellipse, { x: 9.55, y: y + 0.06, w: 0.18, h: 0.18, fill: { color: P.accent } });
    s.addText(t, {
      x: 9.85, y, w: 2.8, h: 0.5,
      fontFace: SANS, fontSize: 10.5, color: P.body, margin: 0,
    });
  });

  pageNum(s, 13);
  s.addNotes('Five layers, each depends only on the one below. The right hand column matters: we process malicious files, so the scanner has to defend itself.');
}

/* ================= 14. MODULES ================= */
{
  const s = pres.addSlide();
  rubric(s, '04', 'Module Description and System Design');
  title(s, 'The 22 modules, and what each one owns');

  const groups = [
    ['Getting packages', P.muted, [
      'npm and PyPI clients',
      'Version range resolver',
      'Safe archive unpacking',
      'Manifest and lockfile reader',
      'Dependency tree builder',
    ]],
    ['Reading the code', P.accentD, [
      'Python parser',
      'JavaScript parser',
      'Install script analyser',
      'Typosquat checker',
      'Feature builder',
      'Analysis coordinator',
    ]],
    ['Learning and deciding', P.accentD, [
      'Sample store and dataset builder',
      'Training and evaluation',
      'Scoring at scan time',
      'OSV advisory client',
      'Import name resolver',
      'Call graph and reachability',
    ]],
    ['Delivering results', P.accent, [
      'Scan orchestrator',
      'Plain English explanations',
      'HTML report writer',
      'API and background jobs',
      'Scan history storage',
      'Dashboard',
    ]],
  ];

  groups.forEach(([h, col, items], i) => {
    const x = M + i * 3.06;
    card(s, { x, y: 1.85, w: 2.86, h: 4.35, fill: P.white, line: P.panel2 });
    s.addShape(pres.ShapeType.rect, { x: x + 0.25, y: 2.08, w: 0.28, h: 0.28, fill: { color: col } });
    s.addText(h, {
      x: x + 0.25, y: 2.45, w: 2.4, h: 0.55,
      fontFace: SANS, fontSize: 12, bold: true, color: P.body, margin: 0,
    });
    s.addText(
      items.map((t, j) => ({ text: t, options: { bullet: true, breakLine: j < items.length - 1 } })),
      {
        x: x + 0.25, y: 3.02, w: 2.4, h: 3.0,
        fontFace: SANS, fontSize: 10, color: P.muted, paraSpaceAfter: 6, margin: 0,
      }
    );
  });

  s.addText('Detection and reachability are kept apart on purpose. Either one can fail and the scan still returns something useful.', {
    x: M, y: 6.4, w: 11.9, h: 0.35,
    fontFace: SANS, fontSize: 11, italic: true, color: P.muted, margin: 0,
  });

  pageNum(s, 14);
  s.addNotes('Do not read all 22 out. Point at the four groups and say which one you would open first if a panel member asked to see code.');
}

/* ================= 15. RESULTS ================= */
{
  const s = pres.addSlide();
  s.background = { color: P.dark };
  rubric(s, '', 'Where the project stands today', true);
  title(s, 'It is built, trained and working', true);

  const stats = [
    ['0.950', 'F1 score', 'rules baseline gets 0.565'],
    ['1,797', 'packages trained on', '898 malicious, 899 clean'],
    ['97%', 'of CVE noise removed', '92 findings down to 3'],
    ['110', 'tests passing', 'no internet needed'],
  ];
  stats.forEach(([v, k, d], i) => {
    const x = M + i * 3.05;
    s.addText(v, {
      x, y: 2.0, w: 2.85, h: 0.85,
      fontFace: SERIF, fontSize: 40, bold: true, color: P.accent, margin: 0,
    });
    s.addText(k, {
      x, y: 2.9, w: 2.85, h: 0.32,
      fontFace: SANS, fontSize: 12.5, bold: true, color: P.white, margin: 0,
    });
    s.addText(d, {
      x, y: 3.22, w: 2.85, h: 0.4,
      fontFace: SANS, fontSize: 10.5, color: P.onDarkM, margin: 0,
    });
  });

  s.addShape(pres.ShapeType.roundRect, {
    x: M, y: 4.0, w: 6.15, h: 1.85,
    fill: { color: P.darker }, line: { color: '1E3D4D', width: 1 }, rectRadius: 0.06,
  });
  s.addText('The clearest test we have', {
    x: M + 0.32, y: 4.2, w: 5.5, h: 0.3,
    fontFace: SANS, fontSize: 12, bold: true, color: P.accent, margin: 0,
  });
  s.addText('On the same demo project, the rules engine flags six packages. The trained model flags one. Big libraries genuinely do call eval and spawn processes, and the model has learned that this is normal at that size.', {
    x: M + 0.32, y: 4.55, w: 5.5, h: 1.15,
    fontFace: SANS, fontSize: 11.5, color: P.onDark, margin: 0,
  });

  s.addText('What we know is still weak', {
    x: 7.35, y: 4.05, w: 5.3, h: 0.3,
    fontFace: SANS, fontSize: 12, bold: true, color: P.white, margin: 0,
  });
  s.addText(
    [
      { text: 'For npm we can only tell whether a package is imported, not whether the vulnerable function is called.', options: { bullet: true, breakLine: true } },
      { text: 'We miss 55 of the 898 malicious samples.', options: { bullet: true, breakLine: true } },
      { text: 'Our training malware is malware that got caught, so real world recall will be lower.', options: { bullet: true } },
    ],
    {
      x: 7.35, y: 4.4, w: 5.3, h: 1.5,
      fontFace: SANS, fontSize: 11, color: P.onDark, paraSpaceAfter: 6, margin: 0,
    }
  );

  s.addText('Next: widen the vulnerable function database, look into the 55 misses, and add a GitHub Action so it runs on every pull request.', {
    x: M, y: 6.25, w: 11.9, h: 0.4,
    fontFace: SANS, fontSize: 11.5, italic: true, color: P.onDarkM, margin: 0,
  });

  pageNum(s, 15);
  s.addNotes('Say the weaknesses yourself before anyone asks. A panel trusts a student who knows the limits of their own work.');
}

pres.writeFile({ fileName: 'ChainGuard_Review1.pptx' }).then(f => console.log('written:', f));
