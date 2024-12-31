// // Set your publishable key: remember to change this to your live publishable key in production
// // See your keys here: https://dashboard.stripe.com/apikeys
// const stripe = Stripe('pk_test_51NWbl0AnVKG20ORq3ML4Gw1AsRYCKw3P9jwdfdrw47mzRhisAYC24f4nYNnBPitQdTO8buAgd68vLLlTgrp8gGHN002apdwN2j');
// const elements = stripe.elements();
// // Custom styling can be passed to options when creating an Element.
// const style = {
//   base: {
//     // Add your base input styles here. For example:
//     fontSize: '16px',
//     color: '#32325d',
//   },
// };
// // // Create an instance of the card Element.
// const cardNumber = elements.create('cardNumber', { style });
// const cardExpiry = elements.create('cardExpiry', { style });
// const cardCvc = elements.create('cardCvc', { style });

// // // Add instances of the card elements into the `card-number`, `card-expiry`, and `card-cvc` <div>s.
// cardNumber.mount('#card-number');
// cardExpiry.mount('#card-expiry');
// cardCvc.mount('#card-cvc')


// // Create a token or display an error when the form is submitted.
// const form = document.getElementById('payment-form');
// form.addEventListener('submit', async (event) => {
//   event.preventDefault();

//   const { token, error } = await stripe.createToken(cardNumber); // Use cardNumber for creating token

//   if (error) {
//     // Inform the customer that there was an error.
//     const errorElement = document.getElementById('card-errors');
//     errorElement.textContent = error.message;
//   } else {
//     // Send the token to your server.
//     stripeTokenHandler(token);
//   }
// });

// const stripeTokenHandler = (token) => {
//   // Insert the token ID into the form so it gets submitted to the server
//   const form = document.getElementById('payment-form');
//   const hiddenInput = document.createElement('input');
//   hiddenInput.setAttribute('type', 'hidden');
//   hiddenInput.setAttribute('name', 'stripeToken');
//   hiddenInput.setAttribute('value', token.id);
//   form.appendChild(hiddenInput);

//   // Submit the form
//   form.submit();
// }