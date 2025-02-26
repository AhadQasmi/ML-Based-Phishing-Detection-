document.getElementById('check-button').addEventListener('click', () => {
  const url = document.getElementById('url-input').value;
  const resultDiv = document.getElementById('result');
  const loadingDiv = document.getElementById('loading');
  
  loadingDiv.style.display = 'block';  
  resultDiv.textContent = '';  
  
  fetch('http://127.0.0.1:5000/check_url', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',  
    },
    body: JSON.stringify({ url: url }),  
  })
  .then(response => response.json()) 
  .then(data => {
      loadingDiv.style.display = 'none';  

      if (data.result === 'phishing') {
        resultDiv.textContent = 'Phishing!!'; 
        resultDiv.style.color = 'red'; 
      } else if (data.result === 'legitimate') {
        resultDiv.textContent = 'Legitimate';  
        resultDiv.style.color = 'green'; 
      } else {
        resultDiv.textContent = 'Error in URL analysis'; 
        resultDiv.style.color = 'orange';  
      }
  })
  .catch(error => {
      console.error('Error:', error);  
      loadingDiv.style.display = 'none';
      resultDiv.textContent = 'Error in communication'; 
      resultDiv.style.color = 'orange'; 
  });
});
