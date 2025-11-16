// Code JavaScript corrigé pour suivi.php
// Variables globales
const logFile = "<?php echo $_SESSION['current_log']['file']; ?>";
let refreshInterval;
let isCompleted = false;
let lastContent = "";

// Fonction pour rafraîchir le contenu du log et vérifier si terminé
function refreshLog() {
    fetch('get_log.php?file=' + encodeURIComponent(logFile))
        .then(response => response.text())
        .then(data => {
            if (data !== lastContent) {
                // Mettre à jour le contenu du log
                document.getElementById('log-content').innerHTML = formatLogContent(data);
                lastContent = data;
            }
            
            // Vérifier si le traitement est terminé
            if (data.includes('Analyse terminée') || data.includes('Processus terminé') || data.includes('[COMPLETED]')) {
                if (!isCompleted) {
                    console.log("Traitement terminé, redirection vers index.php...");
                    isCompleted = true;
                    
                    // Arrêter le rafraîchissement
                    clearInterval(refreshInterval);
                    
                    // Afficher un message de succès
                    const processingMessage = document.querySelector('.processing-message');
                    processingMessage.innerHTML = 'Traitement terminé avec succès! Redirection en cours...';
                    processingMessage.style.color = '#10b981';
                    
                    // Arrêter l'animation du spinner
                    const spinner = document.querySelector('.spinner');
                    spinner.style.animationPlayState = 'paused';
                    spinner.style.borderTopColor = '#10b981';
                    
                    // Rediriger vers index.php après 2 secondes
                    setTimeout(() => {
                        window.location.href = 'index.php';
                    }, 2000);
                }
            }
        })
        .catch(error => {
            console.error('Erreur lors du chargement du log:', error);
        });
}

// Fonction simplifiée pour coloriser les lignes de log
function formatLogContent(content) {
    const lines = content.split('\n');
    let formattedContent = '';
    
    for (const line of lines) {
        if (line.includes('✅') || line.includes('Réussi') || line.includes('Succès')) {
            formattedContent += `<div class="log-success">${line}</div>`;
        } else if (line.includes('❌') || line.includes('Échec') || line.includes('Erreur')) {
            formattedContent += `<div class="log-error">${line}</div>`;
        } else {
            formattedContent += `<div class="log-line">${line}</div>`;
        }
    }
    
    return formattedContent;
}

// Initialisation au chargement de la page
document.addEventListener('DOMContentLoaded', function() {
    // Première exécution immédiate
    refreshLog();
    
    // Puis rafraîchissement périodique
    refreshInterval = setInterval(refreshLog, 2000);
    
    console.log("Surveillance du traitement initialisée");
});