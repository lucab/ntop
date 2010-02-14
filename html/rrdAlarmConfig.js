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
 * --NOTE-- Make sure to have MochKit >1.4 installed (required base, DOM , Async and signal)
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
	
	var idTBody = 'body';						// id of the Tbody
	var idForm = 'formConfigurator'; 			// id of the form
	var rowSelected = null;
	var highlightColour = '#ffff99';
	var onMouseColor = '#edf3fe';
    
	var numIdEvent=undefined;					//	for removing document onclick
	var onMouseUpIdEvent=undefined;
	
	var totalErrors=0; 							// the number of errors in the input field text
	
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
		
	}
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
	
	var removeError=function(element){
		var firstIndex=element.className.search('error');
		
		if(firstIndex != -1){	//there was an error
			element.className=element.className.replace('error', '');//TODO CAMBIA IL REPLACE
			try{
				element.removeAttribute('title');
				}
			catch(error){//error no attribute
				}
			totalErrors--;
			}
		
	};
	
	var setError=function(element, title){
		element.className+= ' error';
		element.title=title;
		totalErrors++;
	};
	
	/*	Method that control the input fields of the table form, and return 
	 * 	the object containing their values or null if some error occurred,
	 *  the fields in this case will be changed to className error and a proper title
	 *  qill be inserted to explain the error*/
	var validateAndGet=function(){
		
		var fields=getElement(idForm).elements;
		var value=null;
		var currentForm={index: null, data:[]};
		
		for(var i=0; i<fields.length;i++ ){
			removeError(fields[i]);
			if(fields[i].id===idUniqueNode ){
				
				value=parseInt(fields[i].value);
				if(isNaN(value)){
					setError(fields[i], 'The id provided is not a number! Check the config file loaded!');
				}else{
					currentForm.index=value;
				}
				continue;	
			}
			if(fields[i].id===idRrdFile){
				value=fields[i].value;
				if(!value){
					setError(fields[i], 'Field Required!');
				}else{
					currentForm.data.push(value);
				}
				continue;
			}
			if(fields[i].id===idTypeThreshold){
				value=fields[i].value;
				if(!value){
					setError(fields[i], 'Field Required!');
				}else{
					currentForm.data.push(value);
				}
				continue;
			}
			
			if(fields[i].id === idValueThreshold){
				value=fields[i].value;
				
				if(!value || isNaN(value)){
					setError(fields[i], 'Must be a number!')
				}else{
					currentForm.data.push(value);
				}
				
				continue;
			}
			if(fields[i].id === idNumberRepetition){
				value=fields[i].value;
				
				if(!value ||isNaN(value)|| parseInt(value)< 0){
					setError(fields[i], 'Must be a non negative integer!')
				}else{
					currentForm.data.push(parseInt(value));
				}
				
				continue;
			}
			if(fields[i].id===idStartTime){
				value=fields[i].value;
				if(!value){
					setError(fields[i], 'Field Required!');
				}else{
					currentForm.data.push(value);
				}
				continue;
			}
			if(fields[i].id===idEndTime){
				value=fields[i].value;
				if(!value){
					setError(fields[i], 'Field Required!');
				}else{
					currentForm.data.push(value);
				}
				continue;
			}
			
			if(fields[i].id===idActionToTake){
				value=fields[i].value;
				if(!value){
					setError(fields[i], 'Field Required!');
				}else{
					currentForm.data.push(value);
				}
				continue;
			}
			if(fields[i].id === idTimeBeforeNext){
				value=fields[i].value;
				
				if(!value || isNaN(value)|| parseInt(value)< 0){
					setError(fields[i], 'Must be a non negative integer!')
				}else{
					currentForm.data.push(parseInt(value));
				}
				
				continue;
			}	
		}
		if (totalErrors === 0){
			return currentForm;			//no errors found
		}else{
			return null;
		}
	};
	
	
	/** * Specific get and set for the uniqueid textbox of the form** */
	var setIdUnique = function(text) {
		getElement(idUniqueNode).value = text;
	};
	var getIdUnique = function() {
		return parseInt(getElement(idUniqueNode).value);
	};
	/* Deselect the current row (if one) and clear all the texboxes on the form */
	var clearForm = function() {

		//setIdUnique(' ');
		getElement(idForm).reset();
		
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
		var i = 0;
		setIdUnique(rowSelected.cells[i++].innerHTML);
		setInputById(idRrdFile, rowSelected.cells[i++].innerHTML);
		setInputById(idTypeThreshold, rowSelected.cells[i++].innerHTML);
		setInputById(idValueThreshold, rowSelected.cells[i++].innerHTML);
		setInputById(idNumberRepetition, rowSelected.cells[i++].innerHTML);
		setInputById(idStartTime, rowSelected.cells[i++].innerHTML);
		setInputById(idEndTime, rowSelected.cells[i++].innerHTML);
		setInputById(idActionToTake, rowSelected.cells[i++].innerHTML);
		setInputById(idTimeBeforeNext, rowSelected.cells[i++].innerHTML);

	};
	/* Select the clicked row or deselect it */
	var doMainClick = function(e) {
		var tmpRow = e.target();
		if (tmpRow.tagName.toLowerCase() === 'td') {
			// a cell was clicked get the parent as rowSelected
			tmpRow = tmpRow.parentNode;
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
		updateFormFields(rowSelected);
	};
	/* Generate a populated tr row to be inserted in the tbody */
	var makeTBodyRow = function(row) {
		if(row[2]==='above'){//adding the icons to the type threshold cell
			row[2]=[row[2], ' ', IMG({'class':'tooltip', src:"/arrow_up.png",  border:"0"})];
		}
		if(row[2]==='below'){
		
			row[2]=[row[2],' ',IMG( {'class':'tooltip', src:"/arrow_down.png", border:"0"})];
		}
		arrTd = map(partial(TD, tdAttributes), row);
		arrTd[1].align = "left";// the numbers here refers to the colums
		arrTd[2].align = "center";
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
    }
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
		if (e.key().code === 27 /* && toClear */)
			clearForm();
	};
	/*
	 * Update the content of the current selected row, picking the data from
	 * what's on the texfields
	 */
	var updateRow = function() {
		var rowToUPDT = validateAndGet();//getCurrentForm();
		if(	rowToUPDT){
			if (!isNaN(rowToUPDT.index)) { // the index is valid number
				configuration.rows[(rowSelected.rowIndex-1)] = concat([rowToUPDT.index],rowToUPDT.data);
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
			lastUniqueId = parseInt(configuration.rows[lastArrayIndex][0]);
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
		if(configuration.rows!= null ){
			var i=parseInt(configuration.rows[configuration.rows.length-1][0]);
			if(!isNaN(i)){
				setIdUnique((i+1));
			}	
		}
		
	}
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
		connect('addRow', 'onmousedown', updateIndex);
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
	
	/*send a ajax post request with the json values of the table data in the page*/
	var sendData=function (){	
	    var request=getXMLHttpRequest();
		var url=window.location.href;//'http://localhost:3000/python/rrdalarm/save.py';
		var pos=url.lastIndexOf('/');
		
		url=url.substring(0, pos)+'/save.py';
		request.open("POST", url, true);
		request.onreadystatechange= function(){//printSendOK;
			if(request.readyState === 4 && request.status=== 200){
				getElement("result").innerHTML=request.responseText;
			}//else no response
		}
		request.setRequestHeader("Content-Type","application/jsonrequest");
		request.send('jsonString='+JSON.stringify({rows:rows})+'&configFile='+ escape(getElement('configFile').value));
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
		sendData: sendData
	};
}();
