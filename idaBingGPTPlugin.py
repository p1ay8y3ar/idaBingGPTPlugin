import asyncio
from asyncio import Semaphore
import idaapi
import idc
import ida_hexrays
import ida_kernwin
import pkg_resources
import urllib.request
import pip
import os
import json
import threading
import functools
import textwrap
from PyQt5.QtWidgets import QDialog, QHBoxLayout, QVBoxLayout, QLabel, QTextEdit, QPushButton

Chatbot = None
ConversationStyle = None


def check_version(package_name: str = "re-edge-gpt"):
    try:
        pkg_name, installed_version = pkg_resources.get_distribution(
            package_name).project_name, pkg_resources.get_distribution(package_name).version
        response = urllib.request.urlopen(f"https://pypi.org/pypi/{package_name}/json")
        data = json.loads(response.read())
        latest_version = data["info"]["version"]
        if installed_version != latest_version:
            raise Exception("install new dependencies")
    except Exception as e:
        print("[!]{}".format(str(e)))
        pip.main(['install', package_name, '--upgrade'])


def is_module_imported():
    try:
        global Chatbot
        global ConversationStyle
        from re_edge_gpt import Chatbot as ImportedChatBot, ConversationStyle as ImportedStyle
        Chatbot = ImportedChatBot
        ConversationStyle = ImportedStyle
        return True
    except ImportError as e:
        return False


class UserChatBot:
    '''
    we dont need the text contexts
    so create a new client every time
    '''
    sem_send_message = Semaphore(1)
    cookies = None

    def __init__(self, cookies_name: str = "ibgp_cookies.json"):
        cookies_path = os.path.join(idaapi.idadir("plugins"), cookies_name)
        if not os.path.isfile(cookies_path):
            if os.name == 'nt':
                cookies_path = os.path.join(os.getenv('APPDATA'), 'Hex-Rays', 'IDA Pro', 'plugins', cookies_name)
            else:
                cookies_path = os.path.join(os.getenv('HOME'), '.idapro', 'plugins', cookies_name)
            if not os.path.isfile(cookies_path):
                raise ValueError(
                    "[!]You should put ibgp_cookies.json in idapro's plugin folder,go github for more help")
        self.load_cookie(cookies_path)

    def load_cookie(self, cookie_path: str):
        self.cookies = json.loads(open(cookie_path, encoding="utf-8").read())

    async def create_bot(self):
        self.bot = await Chatbot.create(cookies=self.cookies)

    async def send_message(self, prompt: str):
        await self.create_bot()
        response = await self.bot.ask(
            prompt=prompt,
            conversation_style=ConversationStyle.balanced,  # todo
            simplify_response=True
        )
        return response["text"]


def comment_callback(address, view, response):
    # Add newlines at the end of each sentence.
    response = "\n".join(textwrap.wrap(response, 80, replace_whitespace=False))

    # Add the response as a comment in IDA.
    idc.set_func_cmt(address, response, 0)
    # Refresh the window so the comment is displayed properly
    if view:
        view.refresh_view(False)
    print("[*]idaBingGPTPlugin query finished!")


def query_thread(query_prompt: str, cb: functools.partial):
    print("[*]idaBingGPTPlugin is querying,please wait")
    bot = UserChatBot()
    resp = asyncio.run(bot.send_message(prompt=query_prompt))
    ida_kernwin.execute_sync(functools.partial(cb, response=resp), ida_kernwin.MFF_WRITE)


def query_wrapper(query_prompt: str, cb: functools.partial):
    t = threading.Thread(target=query_thread, args=[query_prompt, cb])
    t.start()


class idaBingGPTPlugin_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_SKIP
    help = "go github to get more instructions"
    comment = "Use Bing GPT to find/analysis function in ida pro"
    wanted_name = "idaBingGPTPlugin"
    wanted_hotkey = ""
    version = "1.1.0"
    explain_action = "ibgp:explain_function"
    vuln_action = "ibgp:vuln_function"
    exp_action = "ibgp:exp_function"
    customize_action = "ibgp:customize"
    menu = None

    def init(self):
        if not idaapi.init_hexrays_plugin():
            return idaapi.PLUGIN_SKIP

        print("ida BingGPT plugin ({}) installed Mod by p1ay8y3ar".format(self.version))
        addon = idaapi.addon_info_t()
        addon.id = "com.p1ay8y3ar.ibgp"  # ida bing gpt plugin
        addon.name = "idaBingGPTPlugin"
        addon.producer = "p1ay8y3ar"
        addon.url = "https://github.com/p1ay8y3ar"
        addon.version = "1.0.1"
        idaapi.register_addon(addon)
        customize_exp = idaapi.action_desc_t(self.customize_action,
                                             'Use Your Own Prompt',
                                             CustomizeActionHandler(),
                                             "Ctrl+Alt+I",
                                             "Use Your Own Prompt to analyze",
                                             198)
        action_explain = idaapi.action_desc_t(self.explain_action,
                                              'Analyze this function',
                                              ExplainHandler(),
                                              "Ctrl+Alt+G",
                                              "Use bing's gpt model to analyze this funcion",
                                              199)

        action_vuln = idaapi.action_desc_t(self.vuln_action,
                                           'Finding out if a function is potentially vulnerable',
                                           VulnHandler(),
                                           "Ctrl+Alt+V",
                                           "Use bing's gpt model to found bugs",
                                           199)
        action_exp = idaapi.action_desc_t(self.exp_action,
                                          'Generating exp using python',
                                          ExpHandler(),
                                          "Ctrl+Alt+E",
                                          "Use bing's gpt model to found bugs",
                                          199)

        idaapi.register_action(action_explain)
        idaapi.register_action(action_vuln)
        idaapi.register_action(action_exp)
        idaapi.register_action(customize_exp)

        self.menu = ContextMenuHooks()
        self.menu.hook()
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        pass

    def term(self):
        return


class ContextMenuHooks(idaapi.UI_Hooks):
    def finish_populating_widget_popup(self, form, popup):
        # Add actions to the context menu of the Pseudocode view
        if idaapi.get_widget_type(form) == idaapi.BWN_PSEUDOCODE:
            idaapi.attach_action_to_popup(form, popup, idaBingGPTPlugin_t.customize_action, "idaBingGPTPlugin/")
            idaapi.attach_action_to_popup(form, popup, idaBingGPTPlugin_t.explain_action, "idaBingGPTPlugin/")
            idaapi.attach_action_to_popup(form, popup, idaBingGPTPlugin_t.vuln_action, "idaBingGPTPlugin/")
            idaapi.attach_action_to_popup(form, popup, idaBingGPTPlugin_t.exp_action, "idaBingGPTPlugin/")


class UserCustomizePrompt(QDialog):
    def __init__(self, ctx):
        self._ctx = ctx
        super(UserCustomizePrompt, self).__init__()
        self.setWindowTitle("idaBingGPTPlugin")
        layout_main = QVBoxLayout()
        layout_main.addWidget(QLabel("Your Prompt here:"))
        self.edit_base = QTextEdit()
        layout_main.addWidget(self.edit_base)
        self.btn_cancel = QPushButton("Cancel")
        self.btn_confirm = QPushButton("Confirm")
        layout_size = QHBoxLayout()
        layout_main.addLayout(layout_size)
        layout_main.addWidget(self.btn_confirm)
        self.setLayout(layout_main)

        self.btn_confirm.clicked.connect(self.click_confirm)

        self.show()
        self.exec_()

    def click_cancel(self):
        self.close()

    def click_confirm(self):
        decompiler_output = ida_hexrays.decompile(idaapi.get_screen_ea())
        v = ida_hexrays.get_widget_vdui(self._ctx.widget)
        query_wrapper(self.edit_base.toPlainText() + "\n"
                      + str(
            decompiler_output),
                      functools.partial(comment_callback, address=idaapi.get_screen_ea(), view=v))

        self.click_cancel()


class CustomizeActionHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        UserCustomizePrompt(ctx)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class VulnHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        decompiler_output = ida_hexrays.decompile(idaapi.get_screen_ea())
        v = ida_hexrays.get_widget_vdui(ctx.widget)
        # todo
        query_wrapper(str(decompiler_output) + "\nFind possible vulnerability in function",
                      functools.partial(comment_callback, address=idaapi.get_screen_ea(), view=v))
        return 1

    # This action is always available.
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class ExpHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        decompiler_output = ida_hexrays.decompile(idaapi.get_screen_ea())
        v = ida_hexrays.get_widget_vdui(ctx.widget)
        query_wrapper("Find the vulnerability in the following codes\n"
                      + str(
            decompiler_output) + "\nCan you use python pwntools to generate an exp or poc to verify this vulnerability?",
                      functools.partial(comment_callback, address=idaapi.get_screen_ea(), view=v))
        return 1

    # This action is always available.
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class ExplainHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        decompiler_output = ida_hexrays.decompile(idaapi.get_screen_ea())
        v = ida_hexrays.get_widget_vdui(ctx.widget)
        query_wrapper("Can you explain what the following codes does and then analyze it in detail?\n"
                      + str(decompiler_output),
                      functools.partial(comment_callback, address=idaapi.get_screen_ea(), view=v))
        return 1

    # This action is always available.
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


def PLUGIN_ENTRY():
    check_version()
    is_module_imported()
    return idaBingGPTPlugin_t()
