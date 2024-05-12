document.addEventListener('DOMContentLoaded', () => {
    const hashInput = document.getElementById('hashInput');
    const checkButton = document.getElementById('checkButton');
    const characterCounter = document.getElementById('characterCounter');
    const analysisResultContainer = document.getElementById('analysisResult');
    let copyButton = null;
    const maxLines = 500;
    const uniqueResults = new Set(); 

    characterCounter.textContent = `(0/${maxLines})`;

    hashInput.addEventListener('input', () => {
        let inputText = hashInput.value;
        let lines = inputText.split('\n').filter(line => line.trim() !== '');

        if (lines.length > maxLines) {
            lines = lines.slice(0, maxLines);
            inputText = lines.join('\n');
            hashInput.value = inputText;
        }

        const lineCount = lines.length;
        characterCounter.textContent = `(${lineCount}/${maxLines})`;

        checkButton.disabled = lineCount === 0 || lineCount > maxLines;
    });

    checkButton.addEventListener('click', async () => {
        const inputText = hashInput.value.trim();
        if (inputText === '') {
            return;
        }

        
        resetUI();

        let lines = inputText.split('\n').filter(line => line.trim() !== '');
        lines = lines.slice(0, maxLines);
        const uniqueLines = Array.from(new Set(lines)); 

        hashInput.disabled = true;
        checkButton.disabled = true;

        try {
            const response = await fetch('/checkEntries', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ entries: uniqueLines })
            });

            if (!response.ok) {
                throw new Error(`Server returned ${response.status}`);
            }

            const reader = response.body.getReader();
            let result = '';

            while (true) {
                const { done, value } = await reader.read();

                if (done) {
                    break;
                }

                result += new TextDecoder().decode(value);
                const lines = result.split('\n');

                for (const line of lines) {
                    if (line.trim() !== '') {
                        const parsedResult = JSON.parse(line);

                        
                        const resultString = JSON.stringify(parsedResult);
                        if (!uniqueResults.has(resultString)) {
                            uniqueResults.add(resultString);

                            
                            displayAnalysisResult(parsedResult);

                            
                            showCopyButton();
                        }
                    }
                }
            }

        } catch (error) {
            console.error('Error occurred:', error);
            flashErrorMessage('API limit has been reached or there\'s no connection to the server. Please try again later.');
        } finally {
            hashInput.disabled = false;
            checkButton.disabled = false;
        }
    });

    function resetUI() {
        
        analysisResultContainer.innerHTML = '';
        uniqueResults.clear();
        
       
        removeCopyButton();
    }

    function displayAnalysisResult(result) {
        const listItem = document.createElement('li');

        if (result.type === 'Hash') {
            if (result.result.status === 'Malicious') {
                listItem.textContent = `Hash: ${result.result.hash} (${result.result.type}) - ${result.result.enginesDetected} security vendors flagged this file as malicious`;
                listItem.style.color = 'red';
            } else if (result.result.status === 'Clean') {
                listItem.textContent = `Hash: ${result.result.hash} (${result.result.type}) - Clean`;
                listItem.style.color = 'green';
            } else {
                listItem.textContent = `Hash: ${result.result.hash} (${result.result.type}) - No matches found`;
                listItem.style.color = 'gray';
            }
        } else if (result.type === 'IP') {
            const ipData = result.result.data;
            const ipdetection = ipData.attributes.last_analysis_stats.malicious;

            listItem.textContent = `IP Address: ${ipData.id} - ${ipdetection} security vendors flagged this IP address as malicious`;

            
            if (ipdetection > 0) {
                listItem.style.color = 'red';
            } else {
                listItem.style.color = 'green';
            }
        }

        analysisResultContainer.appendChild(listItem);
    }

    function showCopyButton() {
        if (!copyButton) {
            copyButton = document.createElement('button');
            copyButton.textContent = 'Copy Results';
            copyButton.classList.add('copyButton');
            copyButton.addEventListener('click', () => {
                const textToCopy = Array.from(analysisResultContainer.children)
                    .map(li => li.textContent)
                    .join('\n');
                copyToClipboard(textToCopy);
            });
            
            
            analysisResultContainer.parentNode.appendChild(copyButton);
        }
    }

    function removeCopyButton() {
        if (copyButton && copyButton.parentNode) {
            copyButton.parentNode.removeChild(copyButton);
            copyButton = null;
        }
    }

    function flashErrorMessage(message) {
        const flashMessage = document.createElement('div');
        flashMessage.textContent = message;
        flashMessage.classList.add('flashMessage');
        document.body.appendChild(flashMessage);

        setTimeout(() => {
            flashMessage.remove();
        }, 4000);
    }

    function copyToClipboard(text) {
        navigator.clipboard.writeText(text)
            .then(() => {
                showCopyMessage();
            })
            .catch(err => {
                console.error('Failed to copy:', err);
            });
    }

    function showCopyMessage() {
        const copyMessage = document.createElement('div');
        copyMessage.textContent = 'Results copied to clipboard';
        copyMessage.classList.add('copyMessage');
        document.body.appendChild(copyMessage);

        setTimeout(() => {
            copyMessage.style.opacity = '0';
            setTimeout(() => {
                copyMessage.remove();
            }, 1000);
        }, 2000);
    }
});
