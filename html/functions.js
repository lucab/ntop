/**
 * Sets/unsets the pointer in browse mode
 *
 * @param   object   the table row
 * @param   object   the color to use for this row
 * @param   object   the background color
 *
 * @return  boolean  whether pointer is set or not
 */
function setPointer(theRow, thePointerColor, theNormalBgColor)
{
    var theCells = null;

    if (thePointerColor == '' || typeof(theRow.style) == 'undefined') {
        return false;
    }
    if (typeof(document.getElementsByTagName) != 'undefined') {
        theCells = theRow.getElementsByTagName('th');
    }
    else if (typeof(theRow.cells) != 'undefined') {
        theCells = theRow.cells;
    }
    else {
        return false;
    }

    var rowCellsCnt  = theCells.length;
    var currentColor = null;
    var newColor     = null;
    // Opera does not return valid values with "getAttribute"
    if (typeof(window.opera) == 'undefined'
        && typeof(theCells[0].getAttribute) != 'undefined' && typeof(theCells[0].getAttribute) != 'undefined') {
        currentColor = theCells[0].getAttribute('bgcolor');
        newColor     = (currentColor.toLowerCase() == thePointerColor.toLowerCase())
                     ? theNormalBgColor
                     : thePointerColor;
        for (var c = 0; c < rowCellsCnt; c++) {
            theCells[c].setAttribute('bgcolor', newColor, 0);
        } // end for
    }
    else {
        currentColor = theCells[0].style.backgroundColor;
        newColor     = (currentColor.toLowerCase() == thePointerColor.toLowerCase())
                     ? theNormalBgColor
                     : thePointerColor;
        for (var c = 0; c < rowCellsCnt; c++) {
            theCells[c].style.backgroundColor = newColor;
        }
    }

    // --------------------
 if (typeof(document.getElementsByTagName) != 'undefined') {
        theCells = theRow.getElementsByTagName('td');
    }
    else if (typeof(theRow.cells) != 'undefined') {
        theCells = theRow.cells;
    }
    else {
        return false;
    }

    var rowCellsCnt  = theCells.length;
    var currentColor = null;
    var newColor     = null;
    // Opera does not return valid values with "getAttribute"
    if (typeof(window.opera) == 'undefined'
        && typeof(theCells[0].getAttribute) != 'undefined' && typeof(theCells[0].getAttribute) != 'undefined') {
        currentColor = theCells[0].getAttribute('bgcolor');
        newColor     = (currentColor.toLowerCase() == thePointerColor.toLowerCase())
                     ? theNormalBgColor
                     : thePointerColor;
        for (var c = 0; c < rowCellsCnt; c++) {
            theCells[c].setAttribute('bgcolor', newColor, 0);
        } // end for
    }
    else {
        currentColor = theCells[0].style.backgroundColor;
        newColor     = (currentColor.toLowerCase() == thePointerColor.toLowerCase())
                     ? theNormalBgColor
                     : thePointerColor;
        for (var c = 0; c < rowCellsCnt; c++) {
            theCells[c].style.backgroundColor = newColor;
        }
    }

    return true;
} // end of the 'setPointer()' function


function popUp(url) {
		sealWin=window.open(url,"win",'toolbar=no,width=570,height=200');
		sealWin.focus();
}

function confirmDelete() {
   return confirm("Are you sure you want to delete this interface ?");
}

function confirmReset() {
   return confirm("Are you sure you want to reset all statistics ?");
}

function confirmShutdown() {
   return confirm("Are you sure you want to shutdown NTOP?");
}


/* Check SVG browser support */
var hasSVGSupport = false;  // does client have SVG support?
if (navigator.mimeTypes != null && navigator.mimeTypes.length > 0)
{
   if ((navigator.mimeTypes["image/svg+xml"] != null) || (navigator.mimeTypes["image/svg-xml"] != null))
    {
        hasSVGSupport = true;
    }
}


