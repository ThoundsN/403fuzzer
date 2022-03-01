from burp import IContextMenuFactory

from java.util import LinkedList
from javax.swing import JMenuItem
from java.awt.event import ActionListener

from thread import start_new_thread



class MenuImpl(IContextMenuFactory):
    def __init__(self, extender):
        self._extender = extender


    def createMenuItems(self, invocation):
        responses = invocation.getSelectedMessages()
        if responses > 0:
            ret = LinkedList()

            requestMenuItem = JMenuItem("Send request to 403 fuzzing")

            for response in responses:
                requestMenuItem.addActionListener(HandleMenuItems(self._extender,response, "request"))
            ret.add(requestMenuItem)
            return ret
        return None


class HandleMenuItems(ActionListener):
    def __init__(self, extender, messageInfo, menuName):
        self._extender = extender
        self._messageInfo = messageInfo
        self._menuName = menuName


    def actionPerformed(self, e):
        if self._menuName == "request":
            start_new_thread(self._extender.fuzz,( self._messageInfo,))
