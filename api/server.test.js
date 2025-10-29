const request = require('supertest')
const db = require('../data/dbConfig')
const server = require('./server')

beforeAll(async () => {
  await db.migrate.rollback()
  await db.migrate.latest()
})

beforeEach(async () => {
  await db('users').truncate()
})

afterAll(async () => {
  await db.destroy()
})

describe('Auth and jokes endpoints', () => {
  test('register fails when missing username or password', async () => {
    const res = await request(server).post('/api/auth/register').send({ username: 'a' })
    expect(res.status).toBe(400)
    expect(res.body).toEqual({ message: 'username and password required' })
  })

  test('register succeeds and returns created user with id, username, password', async () => {
    const res = await request(server).post('/api/auth/register').send({ username: 'user1', password: 'pw' })
    expect(res.status).toBe(201)
    expect(res.body).toHaveProperty('id')
    expect(res.body).toMatchObject({ username: 'user1' })
    expect(typeof res.body.password).toBe('string')
    expect(res.body.password).not.toBe('pw')
  })

  test('login fails when missing username or password', async () => {
    const res = await request(server).post('/api/auth/login').send({ username: 'user1' })
    expect(res.status).toBe(400)
    expect(res.body).toEqual({ message: 'username and password required' })
  })

  test('login fails with invalid credentials', async () => {
    await request(server).post('/api/auth/register').send({ username: 'user1', password: 'pw' })
    const res = await request(server).post('/api/auth/login').send({ username: 'user1', password: 'wrong' })
    expect(res.status).toBe(401)
    expect(res.body).toEqual({ message: 'invalid credentials' })
  })

  test('login succeeds and returns token and welcome message', async () => {
    await request(server).post('/api/auth/register').send({ username: 'user1', password: 'pw' })
    const res = await request(server).post('/api/auth/login').send({ username: 'user1', password: 'pw' })
    expect(res.status).toBe(200)
    expect(res.body).toHaveProperty('token')
    expect(res.body).toMatchObject({ message: 'welcome, user1' })
  })

  test('jokes are protected: missing token yields 401 and specific message', async () => {
    const res = await request(server).get('/api/jokes')
    expect(res.status).toBe(401)
    expect(res.body).toEqual({ message: 'token required' })
  })

  test('jokes are protected: invalid token yields 401 and specific message', async () => {
    const res = await request(server).get('/api/jokes').set('Authorization', 'not-a-valid-token')
    expect(res.status).toBe(401)
    expect(res.body).toEqual({ message: 'token invalid' })
  })

  test('jokes return data when provided a valid token', async () => {
    await request(server).post('/api/auth/register').send({ username: 'user1', password: 'pw' })
    const login = await request(server).post('/api/auth/login').send({ username: 'user1', password: 'pw' })
    const token = login.body.token
    const res = await request(server).get('/api/jokes').set('Authorization', token)
    expect(res.status).toBe(200)
    expect(Array.isArray(res.body)).toBe(true)
    expect(res.body).toHaveLength(3)
  })
})
