#!/usr/bin/env python3

import argparse
from bs4 import BeautifulSoup
import email
from email import policy
from enum import Enum
import numpy
import re

"""
For machine learning:

import pandas
import pickle
import sklearn
"""

LOW_RISK = 1
DEFAULT_RISK = 2
ELEVATED_RISK = 3
SEVERE_RISK = 5
CERTAIN_DOOM = 10

class Actions(Enum):
    NOTHING = 0
    REMIND_RISK = 1
    WARN = 2
    BLOCK = 3

"""
States: {Phishing email, spam, legitimate email} (Partially observable)
Actions: {Block email, warn, do nothing} (Warnings could have 2 or 3 levels)
Consequences: Blocking phishing an spam emails prevents users from getting scammed,
                blocking legitimate mail prevents users from doing their jobs,
                warning users about phishing and spam decreases the likelihood they will fall for a scam,
                warning users about legitimate email increases the time spent reading email and potentially obstructs legitimate work,
                doing nothing about phishing and spam leaves users open to cyber attacks and phishing scams,
                doing nothing about legitimate email allows users to complete their jobs without interruption
Goals: Protect users from phishing attempts without severely interrupting normal workflow or blocking legitimate emails
Utilities: High utility for blocking phishing and spam emails,
            Low utility for blocking legitimate emails,
            Moderately high utility for warning about phishing and spam emails,
            Moderately low utility for warning about legitimate emails,
            Low utility for doing nothing to phishing and spam emails,
            High utility for doing nothing to legitimate emails

Risk-seeking strategy: Block everything with any signs of potential phishing
Risk-neutral strategy: Block obvious phishing/spam, warn about potential phishing, do nothing if no detection rules are triggered
Risk-averse strategy: Warn about any signs of potential phishing, and do nothing otherwise
"""

class RiskStrategy(Enum):
    NEUTRAL = 0
    AVERSE = 1
    SEEKING = 2

"""
Implemented:
* Increase phishing probability for words with urgency (e.g. URGENT, act fast, act now)
* Slightly increase phishing probability for links
* Slightly increase phishing probability for attachments
* Significantly increase phishing probability for executable attachments
* Report phishing if display text contains a URL that does not match src
* Increase phishing probability for "Click Here"
* Increase phishing probability for buttons
* Increase phishing probability for <script> tags
* Report phishing if <script> uses onclick() method
* Increase phishing probability for generic greeting (e.g. "Hello,\n", "Dear customer", "valued customer", "Greetings,\n"
* Significantly increase phishing probability for "kindly"
* Report phishing for numbers or symbols in email domain name
* Increase phishing probability for Received header that doesn't match from address

TODO: 
- Report phishing for attachments that are viruses (use VirusTotal API)
- Report phishing for malicious links (use VirusTotal API)
- Report phishing for malicious scripts or embedded images (use VirusTotal API)
- Increase phishing probability for misspelled words
- Increase phishing probability for first-time senders
- Increase phishing probability for embedded SVGs
- Add support for I18n
- Report which phishing indicators were found
- Allow multiple emails to be scanned
"""

class FullAnalysis:
    def __init__(self, eml_file, risk_strategy=RiskStrategy.NEUTRAL,
                 block_threshold=(SEVERE_RISK + 1), warn_threshold=ELEVATED_RISK):
        self.risk_strategy = risk_strategy
        self.block_threshold = block_threshold
        self.warn_threshold = warn_threshold
        self._enable_block = True
        self._enable_warn = True
        self._indicators = []
        self._eml = None
        self._auth_results = None
        self._subject = None
        self._body = None
        self._html = None
        self.set_email(eml_file)

        if self.risk_strategy == RiskStrategy.SEEKING:
            self.block_threshold = DEFAULT_RISK
            self.warn_threshold = args.block / 2

        if self.risk_strategy == RiskStrategy.AVERSE or self.block_threshold == -1:
            self._enable_block = False

        if self.warn_threshold == -1:
            self._enable_warn = False

    def set_email(self, eml_file):
        self._eml = email.message_from_file(open(eml_file), policy=policy.default)
        self._auth_results = self._eml["Authentication-Results"]
        self._subject = self._eml["Subject"]
        self._body = self._eml.get_body().as_string()

        for part in self._eml.walk():
            if part.get_content_type() == "text/x-amp-html":
                self._html = BeautifulSoup(part.get_content(), "html.parser")
                return
        self._html = BeautifulSoup(self._body, "html.parser")

    def get_email(self):
        return self._eml

    def get_phishing_indicators(self):
        return self._indicators

    def __get_spoof_risk(self):
        risk = 0

        if "Authentication-Results" not in self._eml:
            self._indicators.append("Mail server skipped authentication checks")
            risk += ELEVATED_RISK
        else:
            if "dkim=pass" not in self._auth_results:
                self._indicators.append("DKIM failed")
                risk += ELEVATED_RISK
            if "dmarc=pass" not in self._auth_results:
                self._indicators.append("DMARC failed")
                risk += ELEVATED_RISK

        if "Received-SPF" not in self._eml:  # Check if the email sever verified the sender's domain
            if self._auth_results is not None and "spf=pass" not in self._auth_results:
                self._indicators.append("The sender's domain could not be verified")
                risk += ELEVATED_RISK
        elif "pass" not in self._eml["Received-SPF"]:  # Check if the sender's domain is spoofed
            self._indicators.append("The sender's domain is spoofed")
            risk += CERTAIN_DOOM

        # Check if sender address contains numbers or special characters
        if re.search(r".+@.*[^a-zA-Z\-\.<>\n]+.*", self._eml["From"]):
            self._indicators.append("The sender's domain contains numbers or special characters")
            risk += CERTAIN_DOOM

        return risk

    def __get_js_risk(self):
        click_handlers = self._html.select("[onclick]") # Any elements with an onclick attribute will run JavaScript when clicked
        if len(click_handlers) > 0: # If any of these exist, they are most likely malicious
            self._indicators.append("One or more elements of this email will execute JavaScript code when clicked")
            return CERTAIN_DOOM
        scripts = self._html.find_all("script")
        if len(scripts) > 0: # There is a very high risk of having JavaScript enabled in an email
            self._indicators.append("JavaScript code will be run when this email is opened")
            return SEVERE_RISK
        else:
            return 0

    def __get_link_risk(self):
        risk = 0
        links = self._html.find_all("a")
        for link in links:
            if risk < DEFAULT_RISK: # Any links are a little sketchy
                self._indicators.append("This email contains hyperlinks")
                risk = DEFAULT_RISK

            # A link with display text containing a URL that does match the href attribute is definitely a phishing attempt
            if "://" in link.text and link["href"] not in link.text:
                self._indicators.append("One or more hyperlinks do not go where they claim")
                return CERTAIN_DOOM

            with open("./rules/click.txt") as file: # Links that just say "Click here" are more sus than normal
                click = file.read().splitlines()
                for bait in click:
                    if risk < ELEVATED_RISK and bait.casefold() in link.text.casefold():
                        self._indicators.append("One or more hyperlinks say \"Click here\" " +
                                                "rather than disclosing where they actually go")
                        risk = ELEVATED_RISK
        return risk

    def __get_button_risk(self):
        buttons = self._html.find_all("button")
        if len(buttons) > 0:
            self._indicators.append("This email contains one or more buttons which could execute malicious code " +
                                    "or redirect the user to a malicious website")
            return ELEVATED_RISK
        else:
            return 0

    def __get_attachment_risk(self):
        attach = False
        exe = False
        virus = False

        for part in self._eml.walk():
            if part.is_attachment():  # Check if the email has attachments
                attach = True
                with open("./rules/executable-extensions.txt") as file: # Check if the attachments are executable
                    exts = file.read().splitlines()
                    for ext_filter in exts:
                        if re.search(ext_filter, part.get_filename()):
                            exe = True

        if virus:
            self._indicators.append("One or more attachments to this email is a virus")
            return CERTAIN_DOOM
        if exe:
            self._indicators.append("One or more attachments to this email is executable")
            return SEVERE_RISK
        if attach:
            self._indicators.append("This email contains one or more attachments")
            return DEFAULT_RISK
        else:
            return 0

    def __get_urgency_risk(self):
        with open("./rules/urgency.txt") as file:
            urgency = file.read().splitlines()
            for line in urgency:
                if line.casefold() in self._subject.casefold() or line.casefold() in self._body.casefold():
                    self._indicators.append("The subject or body urges the user to act quickly without thinking")
                    return ELEVATED_RISK
            return 0

    def __get_greeting_risk(self):
        with open("./rules/generic-greetings.txt") as file:
            generic_greet = file.read().splitlines()
            for greeting in generic_greet:
                greeting = greeting.replace(r"\n", "\n").casefold()
                if greeting in self._body.casefold():
                    self._indicators.append("This email has a generic greeting")
                    return DEFAULT_RISK
            return 0

    def __get_uncommon_text_risk(self):
        with open("./rules/uncommon-text.txt") as file:
            uncommon = file.read().splitlines()
            for phrase in uncommon:
                if phrase.casefold() in self._body.casefold():
                    self._indicators.append("This email contains uncommon language for native English speakers")
                    return ELEVATED_RISK
            return 0

    def get_phish_risk(self):
        risk = 0

        risk += self.__get_spoof_risk()
        risk += self.__get_js_risk()
        risk += self.__get_link_risk()
        risk += self.__get_button_risk()
        risk += self.__get_attachment_risk()
        risk += self.__get_urgency_risk()
        risk += self.__get_greeting_risk()
        risk += self.__get_uncommon_text_risk()

        return risk

    def select_action(self, verbose):
        risk = self.get_phish_risk()
        nothing_utility = float(self.block_threshold - risk)
        remind_risk_utility = self.block_threshold - abs(self.warn_threshold / 2.0 - risk)
        warn_utility = self.block_threshold - abs((self.warn_threshold + self.block_threshold) / 2.0 - risk)
        block_utility = float(risk)

        if not self._enable_warn:
            warn_utility = -float("inf")
        if not self._enable_block:
            block_utility = -float("inf")

        if verbose:
            print("Do nothing:", nothing_utility)
            print("Remind risk:", remind_risk_utility)
            print("Warn:", warn_utility)
            print("Block:", block_utility)
            print()

        return Actions(numpy.argmax(numpy.array([nothing_utility,
                                                 remind_risk_utility,
                                                 warn_utility,
                                                 block_utility])))

if __name__ == "__main__":
    DEFAULT_SEVERE_WARN_THRESHOLD = ELEVATED_RISK
    DEFAULT_BLOCK_THRESHOLD = SEVERE_RISK + 1

    parser = argparse.ArgumentParser(description="Scan an email for indicators of phishing and " +
                                                 "output a risk assessment with recommendations for the user")
    parser.add_argument("-v", "--verbose", help="increase output verbosity", action="count", default=0)
    parser.add_argument("-b", "--block", help=("an integer representing the risk level at which email is blocked " +
                        "(Default: {}, Disable: -1)".format(DEFAULT_BLOCK_THRESHOLD)), type=int, default=DEFAULT_BLOCK_THRESHOLD)
    parser.add_argument("-w", "--warn",
                        help=("an integer representing the risk level at which a more serious warning is displayed " +
                        "(Default: {}, Disable: -1)".format(DEFAULT_SEVERE_WARN_THRESHOLD)), type=int,
                        default=DEFAULT_SEVERE_WARN_THRESHOLD)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-r", "--risky", help="enable risk-seeking mode (has the same effect as -b={})"
                       .format(DEFAULT_RISK), action="store_true")
    group.add_argument("-a", "--averse", help="enable risk-averse mode (has the same effect as -b=-1)",
                       action="store_true")
    parser.add_argument("-f", "--file", help="email file to screen for phishing")
    args = parser.parse_args()

    if not args.file:
        args.file = input("Please input the path to a file containing an email to screen: ")

    strategy = RiskStrategy.NEUTRAL

    if args.averse:
        strategy = RiskStrategy.AVERSE
    elif args.risky:
        strategy = RiskStrategy.SEEKING

    """
    if args.risky:
        args.block = DEFAULT_RISK
        args.warn = args.block / 2

    enable_block = True
    enable_warn = True

    if args.averse or args.block == -1:
        enable_block = False

    if args.warn == -1:
        enable_warn = False
    """

    analyzer = FullAnalysis(args.file, strategy, args.block, args.warn)
    # eml_risk = analyzer.get_phish_risk()

    action = analyzer.select_action(args.verbose >= 2)

    if action == Actions.BLOCK:
        print("Do not attempt to interact with this email message. It has been flagged as a phishing attempt.")
    elif action == Actions.WARN:
        print("This email shows significant signs of potential phishing. Verify its authenticity before interacting.")
    elif action == Actions.REMIND_RISK:
        print("This email shows potential signs of phishing. Proceed with caution, and verify if unsure.")
    else:
        print("No indicators of phishing were found in this email.")

    if args.verbose >= 1:
        print()
        for indicator in analyzer.get_phishing_indicators():
            print(indicator + ".")

    """
    block_compare = "equal to"
    warn_compare = "equal to"

    if eml_risk > args.block:
        block_compare = "above"
    elif eml_risk < args.block:
        block_compare = "below"

    if eml_risk > args.warn:
        warn_compare = "above"
    elif eml_risk < args.warn:
        warn_compare = "below"
    
    if args.verbose >= 2:
        print()
        print("This email file received a risk score of {}.".format(eml_risk))
        print("This is {} the blocking threshold of {} ".format(block_compare, args.block) +
              "and {} the warning threshold of {}.".format(warn_compare, args.warn))
    """
