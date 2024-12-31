const stripe = Stripe('pk_test_51NWbl0AnVKG20ORq3ML4Gw1AsRYCKw3P9jwdfdrw47mzRhisAYC24f4nYNnBPitQdTO8buAgd68vLLlTgrp8gGHN002apdwN2j');
const options = {
    // Fully customizable with appearance API.
    appearance: { /* ... */ }
  };
  
  // Only need to create this if no elements group exist yet.
  // Create a new Elements instance if needed, passing the
  // optional appearance object.
  const elements = stripe.elements(options);
  
  // Create and mount the Address Element in shipping mode
  const addressElement = elements.create("address", {
    mode: "shipping",
    // autocomplete: {
    //   mode: "google_maps_api",
    //   apiKey: "{YOUR_GOOGLE_MAPS_API_KEY}",
    // },
    allowedCountries: ['SG','MY','US','JP'],
    fields: {
      phone: 'always'
    },
    validation: {
      phone: {
        required: 'always',
      },
    },
  });

  addressElement.mount("#address-element");
  const handleNextStep = async (event) => {
    event.preventDefault(); // Prevent default form submission
    const addressElement = elements.getElement('address');
  
    const {complete, value} = await addressElement.getValue();
  
    if (complete) {
      const form = document.getElementById('address-form');
      const hiddenInput = document.createElement('input');
      hiddenInput.setAttribute('type', 'hidden');
      hiddenInput.setAttribute('name', 'address');
      hiddenInput.setAttribute('value', JSON.stringify(value));

      form.appendChild(hiddenInput);
      console.log('Hidden input value:', hiddenInput.value); // Log the value for debugging

      form.submit();

    }
  };

  document.getElementById('address-form').addEventListener('submit', handleNextStep);
