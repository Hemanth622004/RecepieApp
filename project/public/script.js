document.addEventListener('DOMContentLoaded', () => {
    const ingredientInput = document.getElementById('ingredient');
    const searchBtn = document.getElementById('searchBtn');
    const recipeResults = document.getElementById('recipeResults');
    const logoutLink = document.getElementById('logoutLink'); 

    function checkUserLoginStatus() {
        return true;
    }

    function updateLogoutLinkVisibility() {
        const userIsLoggedIn = checkUserLoginStatus();
        if (userIsLoggedIn) {
            logoutLink.style.display = 'block';
        } else {
            logoutLink.style.display = 'none';
        }
    }

    updateLogoutLinkVisibility();
    logoutLink.addEventListener('click', (event) => {
        window.location.href = 'login.html';
    });
    searchBtn.addEventListener('click', () => {
        const ingredient = ingredientInput.value;
        const appId = 'db8f558f';
        const appKey = '561beab0cded9aa98dcbe83bba6e1b17';
        const apiUrl = `https://api.edamam.com/search?q=${ingredient}&app_id=${appId}&app_key=${appKey}`;

        fetch(apiUrl)
            .then((response) => response.json())
            .then((data) => {
                displayRecipes(data.hits);
            })
            .catch((error) => {
                console.error('Error fetching data:', error);
            });
    });

    function displayRecipes(recipes) {
        recipeResults.innerHTML = '';

        if (recipes.length === 0) {
            recipeResults.innerHTML = '<p>No recipes found.</p>';
        } else {
            const recipeList = document.createElement('ul');

            recipes.forEach((recipe) => {
                const recipeItem = document.createElement('li');
                recipeItem.innerHTML = `
                    <h2>${recipe.recipe.label}</h2>
                    <p>Ingredients: ${recipe.recipe.ingredientLines.join(', ')}</p>
                    <a href="${recipe.recipe.url}" target="_blank">View Recipe</a>
                `;
                recipeList.appendChild(recipeItem);
            });

            recipeResults.appendChild(recipeList);
        }
    }
});
