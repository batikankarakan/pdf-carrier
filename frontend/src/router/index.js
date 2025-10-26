import { createRouter, createWebHistory } from 'vue-router'
import EncryptView from '../views/EncryptView.vue'
import DecryptView from '../views/DecryptView.vue'

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes: [
    {
      path: '/',
      redirect: '/encrypt'
    },
    {
      path: '/encrypt',
      name: 'encrypt',
      component: EncryptView,
      meta: {
        title: 'Encrypt PDF',
        icon: 'lock'
      }
    },
    {
      path: '/decrypt',
      name: 'decrypt',
      component: DecryptView,
      meta: {
        title: 'Decrypt PDF',
        icon: 'unlock'
      }
    }
  ]
})

export default router
