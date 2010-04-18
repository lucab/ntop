/**
 * @author Gianluca Medici 
 * @description	This little extension to javascript provide methods
 *         to costruct and mantain an indexed editable table. The table grows
 *         only from the bottom but any row can be selected and removed (to reindex
 *         and printover of the entire table you must trigger anothe function!).
 *         So far it was maded just for the rrdAlarmConfig table but it 
 *         can be modified and inserted in all kind of pages.
 *         All the value inserted are text based, no check is made!(yet)
 * 
 * --USAGE-- Import MochKit in the page you want to insert this table, import
 * this script and add the data you want to visualize with it:
 * rrdAlarmConfig.setRows(arrayOfRows); 
 * 
 * example: arrayOfRows= [[1,'rrdfile.rrd', 'above', '0.0', '0', 'now-1', 'now', ' ', '0']]
 * 
 * add the line: 
 * addLoadEvent(rrdAlarmConfig.initpage);
 * 
 * --Have Fun!--
 * 
 * --NOTE-- Make sure to have MochKit > 1.4 installed (required base, DOM , Async and signal)
 *  
 * 
 * If you need a grid check extJs or jedit!
 */
var rrdAlarmConfig = function() {
	/** * Private properties ** */

	/* ids of the fields on the form */
	var idUniqueNode = 'uniqueId';
	var idRrdFile = 'rrdFile';
	var idTypeThreshold = 'typeThreshold';
	var idValueThreshold = 'valueThreshold';
	var idNumberRepetition = 'numberRepetition';
	var idStartTime = 'startTime';
	var idEndTime = 'endTime';
	var idActionToTake = 'actionToPerform';
	var idTimeBeforeNext = 'timeBeforeNext';
	var	 idTrToChange= 'trToChange';
	var idActionParameter='actionParameter';
	var idUpdateButton='update';
	var idRemoveRowButton='removeRow';
	
	var idTBody = 'body';						// id of the Tbody
	var idForm = 'formConfigurator';			// id of the form
	var rowSelected = null;
	var highlightColour = '#ffff99';
	var onMouseColor = '#edf3fe';
    
	var numIdEvent=undefined;					//	for removing document onclick
	var onMouseUpIdEvent=undefined;
	
	var totalErrors=0;							// the number of errors in the input field text
	//var regTime2= /^\d+$|^(now)([\+\-]\d+[dhms]$)?$/ig;
	//var regTime3= /((^\d+$)|(^(now)([\+\-]\d+[dhms])?$))/ig;
	var regTime= new RegExp(/(^\d+$|^(now)([\+\-]\d+[dhms])?$)/);
	var tdAttributes = {
		align : 'right'
	};
	
	/*the main object containing all the rows of the table*/
	var configuration = {
		rows : null
	};

	/** * End Private properties ** */

	/** * Private methods ** */
	var checkNameFile=function(stringaNameFile){
		var retString=stringaNameFile;
		retString=retString.replace('\\', '');
		retString=retString.replace('/', '');
		retString=retString.replace(' ', '');
		while (retString.charAt(0)==='.'){
			retString=retString.substring(1,retString.length);
		}
		return retString;
		
	};
	/*var findFromEnd= function(stringa, chr){
		
		for(var len=stringa.length-1;len >0; lenn--){
			if(stringa[len]===chr) return len;
		}
		return -1;
	};*/
	var colourRow = function() {
		if (this !== rowSelected) {
			this.style.backgroundColor = onMouseColor;
		}
	};
	var deColourRow = function() {
		if (this !== rowSelected) {
			this.style.backgroundColor = '';
		}
	};
	
	
	
	var setError=function(element, title){
		element.className+= ' error';
		element.title=title;
		totalErrors++;
	};
	
	
	
	/*	Method that controls the input fields of the table form, and return 
	 * 	the object containing their values or null if some error occurred,
	 *  the fields in this case will be changed to className error and a proper title
	 *  will be inserted to explain it*/
	var validateAndGet=function(){
		
		var fields=getElement(idForm).elements;
		var value=null;
		var currentForm={index: null, data:[]};
		var indx=getElement(idUniqueNode);
		if(indx && indx.innerHTML){
			currentForm.index=indx.innerHTML;
		}
		
			/*if(fields[0].id===idUniqueNode ){
				removeError(fields[0]);	
				value=parseInt(fields[0].value, 10);
				if(isNaN(value)){
					setError(fields[0], 'The id provided is not a number! Check the config file loaded!');
				}else{
					currentForm.index=value;
				}
			}*/
			if(fields[0].id===idRrdFile){
				removeError(fields[0]);
				value=fields[0].value;
				if(!value){
					setError(fields[0], 'Field Required!');
				}else{
					currentForm.data.push(value);
				}
			}
			if(fields[1].id===idTypeThreshold){
				removeError(fields[1]);
				value=fields[1].value;
				if(!value){
					setError(fields[1], 'Field Required!');
				}else{
					currentForm.data.push(value);
				}
			}
			
			if(fields[2].id === idValueThreshold){
				removeError(fields[2]);
				value=fields[2].value;
				
				if(!value || isNaN(value)){
					setError(fields[2], 'Must be a number!');
				}else{
					currentForm.data.push(value);
				}
				
			}
			if(fields[3].id === idNumberRepetition){
				removeError(fields[3]);
				value=fields[3].value;
				
				if(!value ||isNaN(value)|| parseInt(value,10)< 0){
					setError(fields[3], 'Must be a non negative integer!');
				}else{
					currentForm.data.push(parseInt(value,10));
				}
				
			}
			if(fields[4].id===idStartTime){
				removeError(fields[4]);
				value=fields[4].value;
				if(!value){
					setError(fields[4], 'Field Required!');
				}else{
					if(regTime.test(value)){
						currentForm.data.push(value);
					}else{
						setError(fields[4], 'Format Inexact!Check Help.');
					}
				}
			}
			if(fields[5].id===idEndTime){
				removeError(fields[5]);
				value=fields[5].value;
				if(!value){
					setError(fields[5], 'Field Required!');
				}else{
					if(regTime.test(value)){
						currentForm.data.push(value);
					}else{
						setError(fields[5], 'Format Inexact!Check Help.');
					}
				}
			}
			
			if(fields[6].id===idActionToTake){
				removeError(fields[6]);
				
				value=fields[6].value;
				
				if (!value) {
					setError(fields[6], 'Field Required!');
				}else{
					currentForm.data.push(value);
				}
				if(fields[6].value!=='None'){
					if(fields[7].id === idActionParameter){
						removeError(fields[7]);						
						value=fields[7].value;
						
						if (!value) {
							setError(fields[7], 'Field Required!');
						}else{
							if(fields[6].value.search('mail')!== -1 && value.search('@')=== -1){
								setError(fields[7], 'The email address is not correct!');	
							}else{
								currentForm.data.push(value);
							}
						}
					}
				}else{
					fields[7].value=' ';
					currentForm.data.push(fields[7].value);
				}
			}
			
			if(fields[8].id === idTimeBeforeNext){
				removeError(fields[8]);
				value=fields[8].value;
				
				if(!value || isNaN(value)|| parseInt(value,10)< 0){
					setError(fields[8], 'Must be a non negative integer!');
				}else{
					currentForm.data.push(parseInt(value,10));
				}
			}	
		value=null;
		if (totalErrors === 0){
			return currentForm;			//no errors found
		}else{
			return null;
		}
	};
	
	/** Enable buttons associated with a selected row **/
	var enableButtons = function(){
		//enable the update button
		getElement(idUpdateButton).disabled=false;
		//enable the removeRow button
		getElement(idRemoveRowButton).disabled=false;
		
	};
	/** disable buttons associated with a selected row **/	
	var disableButtons = function(){
		//disable the update button
		getElement(idUpdateButton).disabled=true;
		//disable the remove row button
		getElement(idRemoveRowButton).disabled=true;
	};
	
	/** * Specific get and set for the uniqueid textbox of the form** */
	var setIdUnique = function(text) {
		getElement(idUniqueNode).innerHTML = text;
		
	};
	var getIdUnique = function() {
		return parseInt(getElement(idUniqueNode).innerHTML,10);
	};
	/* Deselect the current row (if one) and clear all the texboxes on the form */
	var clearForm = function() {
		setIdUnique('&nbsp;');
		//setIdUnique(' ');
		getElement(idForm).reset();
		disableButtons();
		if (rowSelected) {
			rowSelected.style.backgroundColor = '';
			rowSelected = null;
		}
		if(totalErrors>0){
			map(removeError, getElement(idForm).elements);
		}
	};
	/** * generic get set for the input boxes of the form** */
	var setInputById = function(id, text) {
		getElement(id).value = text;
	};
	var getInputById = function(id) {
		var elem = getElement(id).value;
		return elem ? elem : " ";
	};
	
	/* Whereever a row is selected the textbox field are accordingly updated */
	var updateFormFields = function(rowSelected) {
		if(rowSelected){
			var Rindex=rowSelected.rowIndex-1;
			var rowValues=configuration.rows[Rindex];
			var i = 0;
			setIdUnique(rowValues[i++]);
			setInputById(idRrdFile, rowValues[i++]);
			setInputById(idTypeThreshold, rowValues[i++]);
			setInputById(idValueThreshold, rowValues[i++]);
			setInputById(idNumberRepetition, rowValues[i++]);
			setInputById(idStartTime, rowValues[i++]);
			setInputById(idEndTime, rowValues[i++]);
			
			setInputById(idActionToTake, rowValues[i++]);
			setInputById(idActionParameter, rowValues[i++]);
			
			setInputById(idTimeBeforeNext, rowValues[i++]);
		}
	};
	/* Select the clicked row or deselect it */
	var doMainClick = function(e) {
		var tmpRow = e.target();
		var tagN=tmpRow.tagName.toLowerCase();
		if ( tagN=== 'td') {
			// a cell was clicked get the parent as rowSelected
			tmpRow = tmpRow.parentNode;
		}
		if(tagN === 'img'|| tagN === 'strong'){
			//an image inside a  cell was clicked get the parent of the parent as rowSelected		
			tmpRow = tmpRow.parentNode.parentNode;
		}
		if (tmpRow === rowSelected) {
			clearForm();
			return;
		}
		if (rowSelected !== null || totalErrors>0) {
			clearForm();
		}
		rowSelected = tmpRow;
		rowSelected.style.backgroundColor = highlightColour;
		enableButtons();
		updateFormFields(rowSelected);
	};
	/* Generate a populated tr row to be inserted in the tbody */
	var makeTBodyRow = function(row) {
		var actionToTake=row[7];
		
		var rowM=row.slice(0,7).concat(row.slice(8,10));				//remove the actiontotake because will not become a td
		//rowM.concat(row.slice(8,10));
		if(row[7]!=='None'){
			rowM[7]=[STRONG(null,row[7]),':',rowM[7]];
		}else{
			rowM[7]=STRONG(null,row[7]);
		}
		var arrTd = map(partial(TD, tdAttributes), rowM);
		arrTd[1].align = "left";// the numbers here refers to the colums
		arrTd[2].align = "center";
		if(rowM[2]==='above'){//adding the icons to the type threshold cell
			appendChildNodes(arrTd[2],[' ',IMG({'class':'tooltip', src:"/arrow_up.png",  border:"0"})]);
		}
		if(rowM[2]==='below'){
		
			appendChildNodes(arrTd[2],[' ',IMG({'class':'tooltip', src:"/arrow_down.png",  border:"0"})]);
		}
		arrTd[7].title=actionToTake;					//set the title to signal the script that will be called
		arrTd[7].align = "left";
		var tmp = TR(null, arrTd);
		connect(tmp, 'onclick', doMainClick);
		connect(tmp, 'onmouseover', colourRow);
		connect(tmp, 'onmouseout', deColourRow);
		return tmp;
	};
	/*
	 * reindex all the rows preserving uniqueness
	 */
	var reIndexRows = function(rows) {
		for (var i = 0; i < rows.length; i++) {
			rows[i][0] = (i+1);
		}
		return rows;
	};
	/*reIndex all the rows of the table and print it again */
    var normalizeTable = function(){
		reIndexRows(configuration.rows);

		var newTable = makeTBody();

		swapDOM(idTBody, newTable);
    };
	/* Generatea populated tbody tag */
	var makeTBody = function() {
		//var indexedRows = reIndexRows(configuration.rows);
		return TBODY({
					id : idTBody
				}, map(makeTBodyRow, configuration.rows));
	}; 
	/*Read all the current values of the input text of the formConfigurator*/
	/*var getCurrentForm = function() {
		//TODO change these controls methods with a global one that change the colour of the unvalid fields
		
		if(isNaN(getIdUnique())){
			alert('The id provided is not a number! Check the config file loaded!');
			return;
		}
		if(isNaN(getInputById(idValueThreshold)) ){
			alert('The value inserted must me a number!');
			return;
		}
		if(isNaN(getInputById(idNumberRepetition)) || Number(getInputById(idNumberRepetition))< 0){
			alert('The number repetition field must contain a non negative integer!');
			return;
		}
		if(isNaN(getInputById(idTimeBeforeNext)) || Number(getInputById(idTimeBeforeNext))< 0){
			alert('The time before next field must contain a non negative integer!');
			return;
		}
		return {
			index : getIdUnique(),
			data : [
					getInputById(idRrdFile), 
					getInputById(idTypeThreshold),
					getInputById(idValueThreshold),
					getInputById(idNumberRepetition),
					getInputById(idStartTime), 
					getInputById(idEndTime),
					getInputById(idActionToTake),
					getInputById(idTimeBeforeNext)]
		};
	};*/
	/* clear the textfield of the form pressing esc */
	var escPressed = function(e) {
		/*
		 * var kC = (window.event) ? // MSIE or Firefox? event.keyCode :
		 * e.keyCode; var Esc = (window.event) ? 27 : e.DOM_VK_ESCAPE; // MSIE :
		 * Firefox
		 */
		if (e.key().code === 27 /* && toClear */){
			clearForm();
			}
	};
	/*
	 * Update the content of the current selected row, picking the data from
	 * what's on the texfields
	 */
	var updateRow = function() {
		if(!rowSelected){
			addRow();
			return;
		}
		var rowToUPDT = validateAndGet();//getCurrentForm();
		if(	rowToUPDT){
			if (!isNaN(rowToUPDT.index)) { // the index is valid number
				configuration.rows[(rowSelected.rowIndex-1)] = [rowToUPDT.index].concat(rowToUPDT.data);
				var newRow = makeTBodyRow(configuration.rows[(rowSelected.rowIndex-1)]);
				swapDOM(getElement(idTBody).childNodes[(rowSelected.rowIndex-1)],
						newRow);
			} else {
				alert("The current uniqueID is not a number or is not valid! Refresh and check the config file!");
			}
		clearForm();

		}

	};
	
	/*
	 * insert a new row at the bottom of the table based on what's on the
	 * texfields
	 */
	var addRow = function() {
		var lastArrayIndex=configuration.rows.length;
		var lastUniqueId=0;
		if(lastArrayIndex>0){
			lastArrayIndex=lastArrayIndex-1;
			lastUniqueId = parseInt(configuration.rows[lastArrayIndex][0],10);
		}
		
		if(isNaN(lastUniqueId)){
			alert("Error inserting new row: unique id not a number!");
			clearForm();
			return;
		}
		var currentForm=validateAndGet();
		if (currentForm){
			var newRow=concat([(lastUniqueId + 1)],currentForm.data);
			configuration.rows.push(newRow);
			appendChildNodes(getElement(idTBody), [makeTBodyRow(configuration.rows[(configuration.rows.length-1)])]);
			clearForm();

		}
	};
	
	/* Update the uniqueID checkbox for an instant onmousedown */
	var updateIndex = function() {
		if(configuration.rows!== null &&!rowSelected){
			var i=0;
			if(configuration.rows && configuration.rows.length>0){
				i=parseInt(configuration.rows[configuration.rows.length-1][0],10);
				}
			if(!isNaN(i)){
				setIdUnique((i+1));
			}
		}
		
	};
	/* Remove the selected row from the array */
	var removeRow = function() {
		if(rowSelected){
			configuration.rows.splice((rowSelected.rowIndex - 1), 1);
	
			removeElement(rowSelected); // remove the row from the page
			clearForm();
		}
	};
	
	/*hide the button load and connect the event to show it again*/
	var restoreText=function(){
		onMouseUpIdEvent=connect("nameFile",'onmouseup' ,createInput);
		getElement("submit").style.visibility="hidden";
	};
	/*if the target of the event is outside the area with the 
	 * specified id restore previous state*/
	var chooseIfRestore=function(e){
		var conf=getElement('configFile');
		conf.value=checkNameFile(conf.value);
		getElement('configFile').value.replace('/', '');
		var tar=e.target().id;
		if(tar !== "nameFile" && tar!== "submit" && tar!== "configFile"){
			disconnect(numIdEvent);
			restoreText();
			
		}
	};
	
	
	/*Print a message on the result id*/
	var printSendOK=function(){
		getElement("result").innerHTML="New configuration sended!";
	};
	
	/** * End of Private Methods ** */

	/** * Public methods ** */

	var initpage = function() {

		var newTable = makeTBody();

		swapDOM(idTBody, newTable);


		connect(document, 'onkeyup', escPressed);
		connect('update', 'onmouseup', updateRow);
		connect('clear', 'onmouseup', clearForm);
		connect('addRow', 'onmouseup', addRow);
		//connect('addRow', 'onmousedown', updateIndex);
		connect('removeRow', 'onmouseup', removeRow);
		onMouseUpIdEvent=connect(idTrToChange, 'onmouseup', createInput);
	};
	var setIdTBody = function(str) {
		idTBody = str;
	};
	var setRows = function(rows) {
		configuration.rows = rows;
	};
		
	/*just render the input button load visible and on the next click out render it invisible again*/
	var createInput=function (){
		getElement("submit").style.visibility="visible";
		disconnect(onMouseUpIdEvent);
		numIdEvent=connect(document,'onclick',chooseIfRestore);
	};
	var writeSaveResult=function(text){
		getElement("result").innerHTML=text;
	};
	/*send a ajax post request with the json values of the table data in the page*/
	var sendData=function (){	
	    var request=getXMLHttpRequest();
		var url=window.location.href;//'http://localhost:3000/python/rrdalarm/save.py';
		var pos=url.lastIndexOf('/');
		var t=null;
		url=url.substring(0, pos)+'/save.py';
		request.open("POST", url, true);
		request.onreadystatechange= function(){//printSendOK;
			if(request.readyState === 4 && request.status=== 200){
				writeSaveResult(request.responseText);
			}//else no response
			if(t){
				clearTimeout(t);
			}
		};
		request.setRequestHeader("Content-Type","application/jsonrequest");
		request.send('jsonString='+JSON.stringify({rows:rows})+'&configFile='+ escape(getElement('configFile').value));
		t=setTimeout(writeSaveResult,1000,'Some error occurred no response from "save.py" after 1 second!');
		writeSaveResult('Waiting for confirmation...');
	};

	var removeError=function(element){
		var firstIndex=element.className.search('error');
		
		if(firstIndex != -1){	//there was an error   && totalErrors>0
			element.className=element.className.replace('error', '');//TODO CAMBIA IL REPLACE
			try{
				element.removeAttribute('title');
				}
			catch(error){//error no attribute
				}
			totalErrors--;
			}
		
	};
	/** * End of Publics Methods ** */

	return {
		/** * declare public properties and methods ** */
		initpage : initpage,
		setIdTBody : setIdTBody,
		setRows : setRows,
		normalizeTable : normalizeTable,
		createInput: createInput,
		restoreText: restoreText,
		writeSaveResult: writeSaveResult,
		sendData: sendData,
		removeError: removeError
	};
}();
